use {
    crate::{broadcast_stage::BroadcastStage, retransmit_stage::RetransmitStage},
    itertools::Itertools,
    lru::LruCache,
    rand::{seq::SliceRandom, Rng, SeedableRng},
    rand_chacha::ChaChaRng,
    solana_gossip::{
        cluster_info::ClusterInfo,
        contact_info::{ContactInfo, Protocol},
        crds::GossipRoute,
        crds_gossip_pull::CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS,
        crds_value::{CrdsData, CrdsValue},
        weighted_shuffle::WeightedShuffle,
    },
    solana_ledger::shred::ShredId,
    solana_runtime::bank::Bank,
    solana_sdk::{
        clock::{Epoch, Slot},
        feature_set,
        genesis_config::ClusterType,
        native_token::LAMPORTS_PER_SOL,
        pubkey::Pubkey,
        signature::{Keypair, Signer},
        timing::timestamp,
    },
    solana_streamer::socket::SocketAddrSpace,
    std::{
        any::TypeId,
        cmp::Reverse,
        collections::HashMap,
        iter::repeat_with,
        marker::PhantomData,
        net::{IpAddr, SocketAddr},
        sync::{Arc, Mutex, RwLock},
        time::{Duration, Instant},
    },
    thiserror::Error,
};

const DATA_PLANE_FANOUT: usize = 200;
pub(crate) const MAX_NUM_TURBINE_HOPS: usize = 4;

// Limit number of nodes per IP address.
const MAX_NUM_NODES_PER_IP_ADDRESS: usize = 10;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Loopback from slot leader: {leader}, shred: {shred:?}")]
    Loopback { leader: Pubkey, shred: ShredId },
}

#[allow(clippy::large_enum_variant)]
enum NodeId {
    // TVU node obtained through gossip (staked or not).
    ContactInfo(ContactInfo),
    // Staked node with no contact-info in gossip table.
    Pubkey(Pubkey),
}

pub struct Node {
    node: NodeId,
    stake: u64,
}

pub struct ClusterNodes<T> {
    pubkey: Pubkey, // The local node itself.
    // All staked nodes + other known tvu-peers + the node itself;
    // sorted by (stake, pubkey) in descending order.
    nodes: Vec<Node>,
    // Reverse index from nodes pubkey to their index in self.nodes.
    index: HashMap<Pubkey, /*index:*/ usize>,
    weighted_shuffle: WeightedShuffle</*stake:*/ u64>,
    _phantom: PhantomData<T>,
}

type CacheEntry<T> = Option<(/*as of:*/ Instant, Arc<ClusterNodes<T>>)>;

pub struct ClusterNodesCache<T> {
    // Cache entries are wrapped in Arc<RwLock<...>>, so that, when needed, only
    // one thread does the computations to update the entry for the epoch.
    cache: Mutex<LruCache<Epoch, Arc<RwLock<CacheEntry<T>>>>>,
    ttl: Duration, // Time to live.
}

pub struct RetransmitPeers<'a> {
    root_distance: usize, // distance from the root node
    children: Vec<&'a Node>,
    // Maps tvu addresses to the first node
    // in the shuffle with the same address.
    addrs: HashMap<SocketAddr, Pubkey>, // tvu addresses
}

impl Node {
    #[inline]
    fn pubkey(&self) -> Pubkey {
        match &self.node {
            NodeId::Pubkey(pubkey) => *pubkey,
            NodeId::ContactInfo(node) => *node.pubkey(),
        }
    }

    #[inline]
    fn contact_info(&self) -> Option<&ContactInfo> {
        match &self.node {
            NodeId::Pubkey(_) => None,
            NodeId::ContactInfo(node) => Some(node),
        }
    }
}

impl<T> ClusterNodes<T> {
    pub(crate) fn submit_metrics(&self, name: &'static str, now: u64) {
        let mut epoch_stakes = 0;
        let mut num_nodes_dead = 0;
        let mut num_nodes_staked = 0;
        let mut num_nodes_stale = 0;
        let mut stake_dead = 0;
        let mut stake_stale = 0;
        for node in &self.nodes {
            epoch_stakes += node.stake;
            if node.stake != 0u64 {
                num_nodes_staked += 1;
            }
            match node.contact_info().map(ContactInfo::wallclock) {
                None => {
                    num_nodes_dead += 1;
                    stake_dead += node.stake;
                }
                Some(wallclock) => {
                    let age = now.saturating_sub(wallclock);
                    if age > CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS {
                        num_nodes_stale += 1;
                        stake_stale += node.stake;
                    }
                }
            }
        }
        num_nodes_stale += num_nodes_dead;
        stake_stale += stake_dead;
        datapoint_info!(
            name,
            ("epoch_stakes", epoch_stakes / LAMPORTS_PER_SOL, i64),
            ("num_nodes", self.nodes.len(), i64),
            ("num_nodes_dead", num_nodes_dead, i64),
            ("num_nodes_staked", num_nodes_staked, i64),
            ("num_nodes_stale", num_nodes_stale, i64),
            ("stake_dead", stake_dead / LAMPORTS_PER_SOL, i64),
            ("stake_stale", stake_stale / LAMPORTS_PER_SOL, i64),
        );
    }
}

impl ClusterNodes<BroadcastStage> {
    pub fn new(
        cluster_info: &ClusterInfo,
        cluster_type: ClusterType,
        stakes: &HashMap<Pubkey, u64>,
    ) -> Self {
        new_cluster_nodes(cluster_info, cluster_type, stakes)
    }

    pub(crate) fn get_broadcast_peer(&self, shred: &ShredId) -> Option<&ContactInfo> {
        let mut rng = get_seeded_rng(/*leader:*/ &self.pubkey, shred);
        let index = self.weighted_shuffle.first(&mut rng)?;
        self.nodes[index].contact_info()
    }
}

impl ClusterNodes<RetransmitStage> {
    pub(crate) fn get_retransmit_addrs(
        &self,
        slot_leader: &Pubkey,
        shred: &ShredId,
        fanout: usize,
    ) -> Result<(/*root_distance:*/ usize, Vec<SocketAddr>), Error> {
        let RetransmitPeers {
            root_distance,
            children,
            addrs,
        } = self.get_retransmit_peers(slot_leader, shred, fanout)?;
        let protocol = get_broadcast_protocol(shred);
        let peers = children.into_iter().filter_map(|node| {
            node.contact_info()?
                .tvu(protocol)
                .ok()
                .filter(|addr| addrs.get(addr) == Some(&node.pubkey()))
        });
        Ok((root_distance, peers.collect()))
    }

    pub fn get_retransmit_peers(
        &self,
        slot_leader: &Pubkey,
        shred: &ShredId,
        fanout: usize,
    ) -> Result<RetransmitPeers, Error> {
        let mut weighted_shuffle = self.weighted_shuffle.clone();
        // Exclude slot leader from list of nodes.
        if slot_leader == &self.pubkey {
            return Err(Error::Loopback {
                leader: *slot_leader,
                shred: *shred,
            });
        }
        if let Some(index) = self.index.get(slot_leader) {
            weighted_shuffle.remove_index(*index);
        }
        let mut addrs = HashMap::<SocketAddr, Pubkey>::with_capacity(self.nodes.len());
        let mut rng = get_seeded_rng(slot_leader, shred);
        let protocol = get_broadcast_protocol(shred);
        let nodes: Vec<_> = weighted_shuffle
            .shuffle(&mut rng)
            .map(|index| &self.nodes[index])
            .inspect(|node| {
                if let Some(node) = node.contact_info() {
                    if let Ok(addr) = node.tvu(protocol) {
                        addrs.entry(addr).or_insert(*node.pubkey());
                    }
                }
            })
            .collect();
        let self_index = nodes
            .iter()
            .position(|node| node.pubkey() == self.pubkey)
            .unwrap();
        let root_distance = if self_index == 0 {
            0
        } else if self_index <= fanout {
            1
        } else if self_index <= fanout.saturating_add(1).saturating_mul(fanout) {
            2
        } else {
            3 // If changed, update MAX_NUM_TURBINE_HOPS.
        };
        let peers = get_retransmit_peers(fanout, self_index, &nodes);
        Ok(RetransmitPeers {
            root_distance,
            children: peers.collect(),
            addrs,
        })
    }

    // Returns the parent node in the turbine broadcast tree.
    // Returns None if the node is the root of the tree or if it is not staked.
    #[allow(unused)]
    fn get_retransmit_parent(
        &self,
        leader: &Pubkey,
        shred: &ShredId,
        fanout: usize,
    ) -> Result<Option<Pubkey>, Error> {
        // Exclude slot leader from list of nodes.
        if leader == &self.pubkey {
            return Err(Error::Loopback {
                leader: *leader,
                shred: *shred,
            });
        }
        // Unstaked nodes' position in the turbine tree is not deterministic
        // and depends on gossip propagation of contact-infos. Therefore, if
        // this node is not staked return None.
        if self.nodes[self.index[&self.pubkey]].stake == 0 {
            return Ok(None);
        }
        let mut weighted_shuffle = self.weighted_shuffle.clone();
        if let Some(index) = self.index.get(leader).copied() {
            weighted_shuffle.remove_index(index);
        }
        let mut rng = get_seeded_rng(leader, shred);
        // Only need shuffled nodes until this node itself.
        let nodes: Vec<_> = weighted_shuffle
            .shuffle(&mut rng)
            .map(|index| &self.nodes[index])
            .take_while(|node| node.pubkey() != self.pubkey)
            .collect();
        let parent = get_retransmit_parent(fanout, nodes.len(), &nodes);
        Ok(parent.map(Node::pubkey))
    }
}

pub fn new_cluster_nodes<T: 'static>(
    cluster_info: &ClusterInfo,
    cluster_type: ClusterType,
    stakes: &HashMap<Pubkey, u64>,
) -> ClusterNodes<T> {
    let self_pubkey = cluster_info.id();
    let nodes = get_nodes(cluster_info, cluster_type, stakes);
    let index: HashMap<_, _> = nodes
        .iter()
        .enumerate()
        .map(|(ix, node)| (node.pubkey(), ix))
        .collect();
    let broadcast = TypeId::of::<T>() == TypeId::of::<BroadcastStage>();
    let stakes: Vec<u64> = nodes.iter().map(|node| node.stake).collect();
    let mut weighted_shuffle = WeightedShuffle::new("cluster-nodes", &stakes);
    if broadcast {
        weighted_shuffle.remove_index(index[&self_pubkey]);
    }
    ClusterNodes {
        pubkey: self_pubkey,
        nodes,
        index,
        weighted_shuffle,
        _phantom: PhantomData,
    }
}

// All staked nodes + other known tvu-peers + the node itself;
// sorted by (stake, pubkey) in descending order.
fn get_nodes(
    cluster_info: &ClusterInfo,
    cluster_type: ClusterType,
    stakes: &HashMap<Pubkey, u64>,
) -> Vec<Node> {
    let self_pubkey = cluster_info.id();
    let should_dedup_addrs = match cluster_type {
        ClusterType::Development => false,
        ClusterType::Devnet | ClusterType::Testnet | ClusterType::MainnetBeta => true,
    };
    // Maps IP addresses to number of nodes at that IP address.
    let mut counts = {
        let capacity = if should_dedup_addrs { stakes.len() } else { 0 };
        HashMap::<IpAddr, usize>::with_capacity(capacity)
    };
    // The local node itself.
    std::iter::once({
        let stake = stakes.get(&self_pubkey).copied().unwrap_or_default();
        let node = NodeId::from(cluster_info.my_contact_info());
        Node { node, stake }
    })
    // All known tvu-peers from gossip.
    .chain(cluster_info.tvu_peers().into_iter().map(|node| {
        let stake = stakes.get(node.pubkey()).copied().unwrap_or_default();
        let node = NodeId::from(node);
        Node { node, stake }
    }))
    // All staked nodes.
    .chain(
        stakes
            .iter()
            .filter(|(_, stake)| **stake > 0)
            .map(|(&pubkey, &stake)| Node {
                node: NodeId::from(pubkey),
                stake,
            }),
    )
    .sorted_by_key(|node| Reverse((node.stake, node.pubkey())))
    // Since sorted_by_key is stable, in case of duplicates, this
    // will keep nodes with contact-info.
    .dedup_by(|a, b| a.pubkey() == b.pubkey())
    .filter_map(|node| {
        if !should_dedup_addrs
            || node
                .contact_info()
                .and_then(|node| node.tvu(Protocol::UDP).ok())
                .map(|addr| {
                    *counts
                        .entry(addr.ip())
                        .and_modify(|count| *count += 1)
                        .or_insert(1)
                })
                <= Some(MAX_NUM_NODES_PER_IP_ADDRESS)
        {
            Some(node)
        } else {
            // If the node is not staked, drop it entirely. Otherwise, keep the
            // pubkey for deterministic shuffle, but strip the contact-info so
            // that no more packets are sent to this node.
            (node.stake > 0u64).then(|| Node {
                node: NodeId::from(node.pubkey()),
                stake: node.stake,
            })
        }
    })
    .collect()
}

fn get_seeded_rng(leader: &Pubkey, shred: &ShredId) -> ChaChaRng {
    let seed = shred.seed(leader);
    ChaChaRng::from_seed(seed)
}

// root     : [0]
// 1st layer: [1, 2, ..., fanout]
// 2nd layer: [[fanout + 1, ..., fanout * 2],
//             [fanout * 2 + 1, ..., fanout * 3],
//             ...
//             [fanout * fanout + 1, ..., fanout * (fanout + 1)]]
// 3rd layer: ...
// ...
// The leader node broadcasts shreds to the root node.
// The root node retransmits the shreds to all nodes in the 1st layer.
// Each other node retransmits shreds to fanout many nodes in the next layer.
// For example the node k in the 1st layer will retransmit to nodes:
// fanout + k, 2*fanout + k, ..., fanout*fanout + k
fn get_retransmit_peers<T: Copy>(
    fanout: usize,
    index: usize, // Local node's index within the nodes slice.
    nodes: &[T],
) -> impl Iterator<Item = T> + '_ {
    // Node's index within its neighborhood.
    let offset = index.saturating_sub(1) % fanout;
    // First node in the neighborhood.
    let anchor = index - offset;
    let step = if index == 0 { 1 } else { fanout };
    (anchor * fanout + offset + 1..)
        .step_by(step)
        .take(fanout)
        .map(|i| nodes.get(i))
        .while_some()
        .copied()
}

// Returns the parent node in the turbine broadcast tree.
// Returns None if the node is the root of the tree.
fn get_retransmit_parent<T: Copy>(
    fanout: usize,
    index: usize, // Local node's index within the nodes slice.
    nodes: &[T],
) -> Option<T> {
    // Node's index within its neighborhood.
    let offset = index.saturating_sub(1) % fanout;
    let index = index.checked_sub(1)? / fanout;
    let index = index - index.saturating_sub(1) % fanout;
    let index = if index == 0 { index } else { index + offset };
    nodes.get(index).copied()
}

impl<T> ClusterNodesCache<T> {
    pub fn new(
        // Capacity of underlying LRU-cache in terms of number of epochs.
        cap: usize,
        // A time-to-live eviction policy is enforced to refresh entries in
        // case gossip contact-infos are updated.
        ttl: Duration,
    ) -> Self {
        Self {
            cache: Mutex::new(LruCache::new(cap)),
            ttl,
        }
    }
}

impl<T: 'static> ClusterNodesCache<T> {
    fn get_cache_entry(&self, epoch: Epoch) -> Arc<RwLock<CacheEntry<T>>> {
        let mut cache = self.cache.lock().unwrap();
        match cache.get(&epoch) {
            Some(entry) => Arc::clone(entry),
            None => {
                let entry = Arc::default();
                cache.put(epoch, Arc::clone(&entry));
                entry
            }
        }
    }

    pub(crate) fn get(
        &self,
        shred_slot: Slot,
        root_bank: &Bank,
        working_bank: &Bank,
        cluster_info: &ClusterInfo,
    ) -> Arc<ClusterNodes<T>> {
        let epoch_schedule = root_bank.epoch_schedule();
        let epoch = epoch_schedule.get_epoch(shred_slot);
        let entry = self.get_cache_entry(epoch);
        if let Some((_, nodes)) = entry
            .read()
            .unwrap()
            .as_ref()
            .filter(|(asof, _)| asof.elapsed() < self.ttl)
        {
            return nodes.clone();
        }
        // Hold the lock on the entry here so that, if needed, only
        // one thread recomputes cluster-nodes for this epoch.
        let mut entry = entry.write().unwrap();
        if let Some((_, nodes)) = entry.as_ref().filter(|(asof, _)| asof.elapsed() < self.ttl) {
            return nodes.clone();
        }
        let epoch_staked_nodes = [root_bank, working_bank]
            .iter()
            .find_map(|bank| bank.epoch_staked_nodes(epoch));
        if epoch_staked_nodes.is_none() {
            inc_new_counter_info!("cluster_nodes-unknown_epoch_staked_nodes", 1);
            if epoch != epoch_schedule.get_epoch(root_bank.slot()) {
                return self.get(root_bank.slot(), root_bank, working_bank, cluster_info);
            }
            inc_new_counter_info!("cluster_nodes-unknown_epoch_staked_nodes_root", 1);
        }
        let nodes = Arc::new(new_cluster_nodes::<T>(
            cluster_info,
            root_bank.cluster_type(),
            &epoch_staked_nodes.unwrap_or_default(),
        ));
        *entry = Some((Instant::now(), Arc::clone(&nodes)));
        nodes
    }
}

impl From<ContactInfo> for NodeId {
    fn from(node: ContactInfo) -> Self {
        NodeId::ContactInfo(node)
    }
}

impl From<Pubkey> for NodeId {
    fn from(pubkey: Pubkey) -> Self {
        NodeId::Pubkey(pubkey)
    }
}

#[inline]
pub(crate) fn get_broadcast_protocol(_: &ShredId) -> Protocol {
    Protocol::UDP
}

pub fn make_test_cluster<R: Rng>(
    rng: &mut R,
    num_nodes: usize,
    unstaked_ratio: Option<(u32, u32)>,
) -> (
    Vec<ContactInfo>,
    HashMap<Pubkey, u64>, // stakes
    ClusterInfo,
) {
    let (unstaked_numerator, unstaked_denominator) = unstaked_ratio.unwrap_or((1, 7));
    let mut nodes: Vec<_> = repeat_with(|| {
        let pubkey = solana_sdk::pubkey::new_rand();
        ContactInfo::new_localhost(&pubkey, /*wallclock:*/ timestamp())
    })
    .take(num_nodes)
    .collect();
    nodes.shuffle(rng);
    let keypair = Arc::new(Keypair::new());
    nodes[0].set_pubkey(keypair.pubkey());
    let this_node = nodes[0].clone();
    let mut stakes: HashMap<Pubkey, u64> = nodes
        .iter()
        .filter_map(|node| {
            if rng.gen_ratio(unstaked_numerator, unstaked_denominator) {
                None // No stake for some of the nodes.
            } else {
                Some((*node.pubkey(), rng.gen_range(0..20)))
            }
        })
        .collect();
    // Add some staked nodes with no contact-info.
    stakes.extend(repeat_with(|| (Pubkey::new_unique(), rng.gen_range(0..20))).take(100));
    let cluster_info = ClusterInfo::new(this_node, keypair, SocketAddrSpace::Unspecified);
    {
        let now = timestamp();
        let mut gossip_crds = cluster_info.gossip.crds.write().unwrap();
        // First node is pushed to crds table by ClusterInfo constructor.
        for node in nodes.iter().skip(1) {
            let node = CrdsData::ContactInfo(node.clone());
            let node = CrdsValue::new_unsigned(node);
            assert_eq!(
                gossip_crds.insert(node, now, GossipRoute::LocalMessage),
                Ok(())
            );
        }
    }
    (nodes, stakes, cluster_info)
}

pub(crate) fn get_data_plane_fanout(shred_slot: Slot, root_bank: &Bank) -> usize {
    if enable_turbine_fanout_experiments(shred_slot, root_bank) {
        // Allocate ~2% of slots to turbine fanout experiments.
        match shred_slot % 359 {
            11 => 64,
            61 => 768,
            111 => 128,
            161 => 640,
            211 => 256,
            261 => 512,
            311 => 384,
            _ => DATA_PLANE_FANOUT,
        }
    } else {
        DATA_PLANE_FANOUT
    }
}

fn enable_turbine_fanout_experiments(shred_slot: Slot, root_bank: &Bank) -> bool {
    check_feature_activation(
        &feature_set::enable_turbine_fanout_experiments::id(),
        shred_slot,
        root_bank,
    ) && !check_feature_activation(
        &feature_set::disable_turbine_fanout_experiments::id(),
        shred_slot,
        root_bank,
    )
}

// Returns true if the feature is effective for the shred slot.
#[must_use]
pub fn check_feature_activation(feature: &Pubkey, shred_slot: Slot, root_bank: &Bank) -> bool {
    match root_bank.feature_set.activated_slot(feature) {
        None => false,
        Some(feature_slot) => {
            let epoch_schedule = root_bank.epoch_schedule();
            let feature_epoch = epoch_schedule.get_epoch(feature_slot);
            let shred_epoch = epoch_schedule.get_epoch(shred_slot);
            feature_epoch < shred_epoch
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        std::{fmt::Debug, hash::Hash},
        test_case::test_case,
    };

    #[test]
    fn test_cluster_nodes_retransmit() {
        let mut rng = rand::thread_rng();
        let (nodes, stakes, cluster_info) = make_test_cluster(&mut rng, 1_000, None);
        // ClusterInfo::tvu_peers excludes the node itself.
        assert_eq!(cluster_info.tvu_peers().len(), nodes.len() - 1);
        let cluster_nodes =
            new_cluster_nodes::<RetransmitStage>(&cluster_info, ClusterType::Development, &stakes);
        // All nodes with contact-info should be in the index.
        // Staked nodes with no contact-info should be included.
        assert!(cluster_nodes.nodes.len() > nodes.len());
        // Assert that all nodes keep their contact-info.
        // and, all staked nodes are also included.
        {
            let cluster_nodes: HashMap<_, _> = cluster_nodes
                .nodes
                .iter()
                .map(|node| (node.pubkey(), node))
                .collect();
            for node in &nodes {
                assert_eq!(
                    cluster_nodes[node.pubkey()]
                        .contact_info()
                        .unwrap()
                        .pubkey(),
                    node.pubkey()
                );
            }
            for (pubkey, stake) in &stakes {
                if *stake > 0 {
                    assert_eq!(cluster_nodes[pubkey].stake, *stake);
                }
            }
        }
    }

    #[test]
    fn test_cluster_nodes_broadcast() {
        let mut rng = rand::thread_rng();
        let (nodes, stakes, cluster_info) = make_test_cluster(&mut rng, 1_000, None);
        // ClusterInfo::tvu_peers excludes the node itself.
        assert_eq!(cluster_info.tvu_peers().len(), nodes.len() - 1);
        let cluster_nodes =
            ClusterNodes::<BroadcastStage>::new(&cluster_info, ClusterType::Development, &stakes);
        // All nodes with contact-info should be in the index.
        // Excluding this node itself.
        // Staked nodes with no contact-info should be included.
        assert!(cluster_nodes.nodes.len() > nodes.len());
        // Assert that all nodes keep their contact-info.
        // and, all staked nodes are also included.
        {
            let cluster_nodes: HashMap<_, _> = cluster_nodes
                .nodes
                .iter()
                .map(|node| (node.pubkey(), node))
                .collect();
            for node in &nodes {
                assert_eq!(
                    cluster_nodes[node.pubkey()]
                        .contact_info()
                        .unwrap()
                        .pubkey(),
                    node.pubkey()
                );
            }
            for (pubkey, stake) in &stakes {
                if *stake > 0 {
                    assert_eq!(cluster_nodes[pubkey].stake, *stake);
                }
            }
        }
    }

    // Checks (1) computed retransmit children against expected children and
    // (2) computed parent of each child against the expected parent.
    fn check_retransmit_nodes<T>(fanout: usize, nodes: &[T], peers: Vec<Vec<T>>)
    where
        T: Copy + Eq + PartialEq + Debug + Hash,
    {
        // Map node identities to their index within the shuffled tree.
        let index: HashMap<_, _> = nodes
            .iter()
            .copied()
            .enumerate()
            .map(|(k, node)| (node, k))
            .collect();
        let offset = peers.len();
        // Root node's parent is None.
        assert_eq!(get_retransmit_parent(fanout, /*index:*/ 0, nodes), None);
        for (k, peers) in peers.into_iter().enumerate() {
            assert_eq!(
                get_retransmit_peers(fanout, k, nodes).collect::<Vec<_>>(),
                peers
            );
            let parent = Some(nodes[k]);
            for peer in peers {
                assert_eq!(get_retransmit_parent(fanout, index[&peer], nodes), parent);
            }
        }
        // Remaining nodes have no children.
        for k in offset..=nodes.len() {
            assert_eq!(get_retransmit_peers(fanout, k, nodes).next(), None);
        }
    }

    #[test]
    fn test_get_retransmit_nodes() {
        // fanout 2
        let nodes = [
            7, // root
            6, 10, // 1st layer
            // 2nd layer
            5, 19, // 1st neighborhood
            0, 14, // 2nd
            // 3rd layer
            3, 1, // 1st neighborhood
            12, 2, // 2nd
            11, 4, // 3rd
            15, 18, // 4th
            // 4th layer
            13, 16, // 1st neighborhood
            17, 9, // 2nd
            8, // 3rd
        ];
        let peers = vec![
            vec![6, 10],
            vec![5, 0],
            vec![19, 14],
            vec![3, 12],
            vec![1, 2],
            vec![11, 15],
            vec![4, 18],
            vec![13, 17],
            vec![16, 9],
            vec![8],
        ];
        check_retransmit_nodes(/*fanout:*/ 2, &nodes, peers);
        // fanout 3
        let nodes = [
            19, // root
            14, 15, 28, // 1st layer
            // 2nd layer
            29, 4, 5, // 1st neighborhood
            9, 16, 7, // 2nd
            26, 23, 2, // 3rd
            // 3rd layer
            31, 3, 17, // 1st neighborhood
            20, 25, 0, // 2nd
            13, 30, 18, // 3rd
            35, 21, 22, // 4th
            6, 8, 11, // 5th
            27, 1, 10, // 6th
            12, 24, 34, // 7th
            33, 32, // 8th
        ];
        let peers = vec![
            vec![14, 15, 28],
            vec![29, 9, 26],
            vec![4, 16, 23],
            vec![5, 7, 2],
            vec![31, 20, 13],
            vec![3, 25, 30],
            vec![17, 0, 18],
            vec![35, 6, 27],
            vec![21, 8, 1],
            vec![22, 11, 10],
            vec![12, 33],
            vec![24, 32],
            vec![34],
        ];
        check_retransmit_nodes(/*fanout:*/ 3, &nodes, peers);
        let nodes = [
            5, // root
            34, 52, 8, // 1st layer
            // 2nd layar
            44, 18, 2, // 1st neigborhood
            42, 47, 46, // 2nd
            11, 26, 28, // 3rd
            // 3rd layer
            53, 23, 37, // 1st neighborhood
            40, 13, 7, // 2nd
            50, 35, 22, // 3rd
            3, 27, 31, // 4th
            10, 48, 15, // 5th
            19, 6, 30, // 6th
            36, 45, 1, // 7th
            38, 12, 17, // 8th
            4, 32, 16, // 9th
            // 4th layer
            41, 49, 24, // 1st neighborhood
            14, 9, 0, // 2nd
            29, 21, 39, // 3rd
            43, 51, 33, // 4th
            25, 20, // 5th
        ];
        let peers = vec![
            vec![34, 52, 8],
            vec![44, 42, 11],
            vec![18, 47, 26],
            vec![2, 46, 28],
            vec![53, 40, 50],
            vec![23, 13, 35],
            vec![37, 7, 22],
            vec![3, 10, 19],
            vec![27, 48, 6],
            vec![31, 15, 30],
            vec![36, 38, 4],
            vec![45, 12, 32],
            vec![1, 17, 16],
            vec![41, 14, 29],
            vec![49, 9, 21],
            vec![24, 0, 39],
            vec![43, 25],
            vec![51, 20],
            vec![33],
        ];
        check_retransmit_nodes(/*fanout:*/ 3, &nodes, peers);
    }

    #[test_case(2, 1_347)]
    #[test_case(3, 1_359)]
    #[test_case(4, 4_296)]
    #[test_case(5, 3_925)]
    #[test_case(6, 8_778)]
    #[test_case(7, 9_879)]
    fn test_get_retransmit_nodes_round_trip(fanout: usize, size: usize) {
        let mut rng = rand::thread_rng();
        let mut nodes: Vec<_> = (0..size).collect();
        nodes.shuffle(&mut rng);
        // Map node identities to their index within the shuffled tree.
        let index: HashMap<_, _> = nodes
            .iter()
            .copied()
            .enumerate()
            .map(|(k, node)| (node, k))
            .collect();
        // Root node's parent is None.
        assert_eq!(get_retransmit_parent(fanout, /*index:*/ 0, &nodes), None);
        for k in 1..size {
            let parent = get_retransmit_parent(fanout, k, &nodes).unwrap();
            let mut peers = get_retransmit_peers(fanout, index[&parent], &nodes);
            assert_eq!(peers.find(|&peer| peer == nodes[k]), Some(nodes[k]));
        }
        for k in 0..size {
            let parent = Some(nodes[k]);
            for peer in get_retransmit_peers(fanout, k, &nodes) {
                assert_eq!(get_retransmit_parent(fanout, index[&peer], &nodes), parent);
            }
        }
    }
}
