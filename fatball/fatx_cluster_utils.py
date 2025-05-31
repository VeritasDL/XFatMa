
# FATX Cluster Chain Utilities

PARTITION_LENGTH = 0xF1A8F2000
PARTITION_OFFSET = 0x2856A0000
SECTORS_PER_CLUSTER = 0x20
SECTOR_SIZE = 0x200
PAGE_SIZE = 0x1000
CLUSTER_SIZE = SECTORS_PER_CLUSTER * SECTOR_SIZE
MAX_CLUSTERS = (PARTITION_LENGTH // CLUSTER_SIZE) + 1
IS_FATX16 = MAX_CLUSTERS < 0xFFF0
CLUSTER_LAST = 0xFFFF if IS_FATX16 else 0xFFFFFFFF
CLUSTER_AVAILABLE = 0x0000

BYTES_PER_FAT = ((((2 if IS_FATX16 else 4) * MAX_CLUSTERS) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
FAT_OFFSET = 0x1000
FILE_AREA_OFFSET = FAT_OFFSET + BYTES_PER_FAT

def get_cluster_offset(cluster):
    if cluster < 1 or cluster > MAX_CLUSTERS:
        raise ValueError("Invalid cluster number")
    return PARTITION_OFFSET + FILE_AREA_OFFSET + ((cluster - 1) * CLUSTER_SIZE)

def resolve_cluster_chain(first_cluster: int, fat_table: list[int]) -> list[int]:
    chain = []
    cluster = first_cluster
    while cluster != CLUSTER_LAST:
        if cluster in chain or cluster >= len(fat_table):
            break
        chain.append(cluster)
        cluster = fat_table[cluster]
    return chain

def zero_cluster_chain(first_cluster: int, fat_table: list[int]) -> None:
    cluster = first_cluster
    while cluster != CLUSTER_LAST:
        if cluster >= len(fat_table):
            break
        next_cluster = fat_table[cluster]
        fat_table[cluster] = CLUSTER_AVAILABLE
        cluster = next_cluster

def read_file_data(file_bytes: bytes, cluster_chain: list[int]) -> bytes:
    data = bytearray()
    for cluster in cluster_chain:
        offset = get_cluster_offset(cluster) - PARTITION_OFFSET
        data += file_bytes[offset:offset + CLUSTER_SIZE]
    return bytes(data)
