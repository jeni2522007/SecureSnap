"""Copy-move and duplicate-region detection.

Copy-move forgery duplicates a region of an image over another region of the
same image to hide something. The classic counter-measure is to search for
blocks that repeat inside the same picture.

A perceptual DCT hash is used so that the match survives the small changes
that compression introduces. All matching is vectorised and bounded, because
a smooth photograph produces thousands of blocks with identical hashes and a
naive pairwise search does not finish.
"""

import os

import cv2
import numpy as np

try:
    from scipy.fft import dctn as _dctn

    _HAS_SCIPY = True
except ImportError:  # pragma: no cover - scipy is an optional accelerator
    _HAS_SCIPY = False

BLOCK_SIZE = 16
STRIDE = 4
HASH_SIZE = 8
BAND_COUNT = 4
BAND_BITS = 16
BAND_MASK = (1 << BAND_BITS) - 1
# A band key may not contribute more than this many candidate blocks.
BAND_KEY_CAP = 24
# Blocks whose exact hash is shared by more blocks than this are treated as
# flat or repetitive areas and are not worth pairwise comparison.
GROUP_CAP = 64
# Upper bound on the number of retained matches, which keeps the clustering
# stage bounded.
MATCH_CAP = 600
# Blocks flatter than this (in 0-255 intensity levels) are ignored because
# they match too easily to be evidence of anything.
MIN_BLOCK_STD = 20.0


def _block_hashes(blocks):
    """Return the DCT perceptual hash of every block, as uint64 values."""
    if blocks.size == 0:
        return np.zeros(0, dtype=np.uint64)

    if _HAS_SCIPY:
        transformed = _dctn(blocks.astype(np.float64), axes=(1, 2), norm="ortho")
    else:  # pragma: no cover - fallback path
        transformed = np.empty(
            (blocks.shape[0], blocks.shape[1], blocks.shape[2]), dtype=np.float64
        )
        for index in range(blocks.shape[0]):
            transformed[index] = cv2.dct(
                 blocks[index].astype(np.float64)
            )
            

    low_frequency = transformed[:, :HASH_SIZE, :HASH_SIZE]

    # Compare each block against its own median so the hash is stable under
    # changes in overall brightness.
    medians = np.median(low_frequency[:, 1:, 1:], axis=(1, 2), keepdims=True)
    bits = (low_frequency > medians).reshape(low_frequency.shape[0], -1)

    weights = (1 << np.arange(bits.shape[1] - 1, -1, -1)).astype(np.uint64)
    return (bits.astype(np.uint64) * weights).sum(axis=1)


def detect_copy_move(file_path, output_folder, block_size=BLOCK_SIZE, stride=STRIDE,
                     threshold=2, min_block_std=MIN_BLOCK_STD):
    """Search an image for duplicated regions.

    Returns the number of matched pairs, the duplicated pixel area and the
    filename of a generated match map.
    """
    os.makedirs(output_folder, exist_ok=True)

    image = cv2.imread(file_path, cv2.IMREAD_GRAYSCALE)
    if image is None:
        return {"available": False, "reason": "Image could not be decoded"}

    height, width = image.shape
    if height < block_size * 2 or width < block_size * 2:
        return {
            "available": False,
            "reason": "Image is too small for block-level comparison",
        }

    # Cap the working size so a very large photo does not stall the analysis.
    scale = 1.0
    if max(height, width) > 1200:
        scale = 1200 / max(height, width)
        working = cv2.resize(
            image, (int(width * scale), int(height * scale)),
            interpolation=cv2.INTER_AREA,
        )
    else:
        working = image

    working_height, working_width = working.shape

    rows = list(range(0, working_height - block_size + 1, stride))
    columns = list(range(0, working_width - block_size + 1, stride))

    if not rows or not columns:
        return {"available": False, "reason": "Not enough blocks to compare"}

    # Gather every block into a single array so the hashes can be computed
    # in one vectorised pass.
    block_count = len(rows) * len(columns)
    blocks = np.empty((block_count, block_size, block_size), dtype=np.uint8)

    position_index = 0
    positions = []
    for y in rows:
        for x in columns:
            blocks[position_index] = working[y:y + block_size, x:x + block_size]
            positions.append((x, y))
            position_index += 1

    hashes = _block_hashes(blocks)
    positions_array = np.array(positions, dtype=np.int32)

    # Flat blocks carry no distinctive information, so matching them only
    # produces false positives on skies, walls and other smooth areas.
    texture = blocks.reshape(block_count, -1).astype(np.float32).std(axis=1)
    informative = texture >= min_block_std

    pairs = _candidate_pairs(hashes, threshold)
    matches = _filter_matches(pairs, hashes, positions_array, block_size, threshold,
                              informative)

    # Group matches into connected regions so we can report clusters.
    regions = _cluster_matches(matches, block_size, scale)

    duplicated_area = sum(region["area_pixels"] for region in regions)
    total_area = height * width

    match_map = np.zeros((height, width), dtype=np.uint8)
    for region in regions:
        source = region["source"]
        copy = region["copy"]
        x1, y1 = source["x"], source["y"]
        x2, y2 = copy["x"], copy["y"]
        match_map[int(y1):int(y1 + region["height"]),
                  int(x1):int(x1 + region["width"])] = 255
        match_map[int(y2):int(y2 + region["height"]),
                  int(x2):int(x2 + region["width"])] = 255

    base_name = os.path.splitext(os.path.basename(file_path))[0]
    map_path = os.path.join(output_folder, f"{base_name}_copymove.png")
    cv2.imwrite(map_path, match_map)

    return {
        "available": True,
        "block_size": block_size,
        "stride": stride,
        "blocks_compared": block_count,
        "match_count": len(matches),
        "regions": regions,
        "regions_count": len(regions),
        "duplicated_area_pixels": int(duplicated_area),
        "duplicated_area_ratio": round(duplicated_area / total_area, 4) if total_area else 0.0,
        "match_map": os.path.basename(map_path),
        "detected": len(regions) > 0,
    }


def _candidate_pairs(hashes, threshold):
    """Return every candidate block pair worth checking.

    Two sources of candidates are combined: blocks whose hash is exactly
    equal, and blocks that share at least two whole 16-bit bands of the
    hash, which is the necessary condition for being within the threshold.
    """
    count = len(hashes)
    if count < 2:
        return np.zeros((0, 2), dtype=np.int64)

    pair_chunks = []

    # 1. Exact hash groups.
    order = np.argsort(hashes, kind="stable")
    sorted_hashes = hashes[order]

    start = 0
    while start < count:
        end = start + 1
        while end < count and sorted_hashes[end] == sorted_hashes[start]:
            end += 1

        group_size = end - start
        if 2 <= group_size <= GROUP_CAP:
            members = order[start:end]
            left, right = np.triu_indices(group_size, k=1)
            pair_chunks.append(np.stack([members[left], members[right]], axis=1))

        start = end

    # 2. Near matches through the banded index.
    band_keys = np.zeros((count, BAND_COUNT), dtype=np.uint64)
    for band in range(BAND_COUNT):
        shift = (BAND_COUNT - 1 - band) * BAND_BITS
        band_keys[:, band] = (hashes >> shift) & BAND_MASK

    for band in range(BAND_COUNT):
        keys = band_keys[:, band]
        order = np.argsort(keys, kind="stable")
        sorted_keys = keys[order]
        boundaries = np.flatnonzero(np.diff(sorted_keys)) + 1
        groups = np.split(order, boundaries)

        for group in groups:
            size = group.size
            if size < 2:
                continue
            if size > BAND_KEY_CAP:
                group = group[:BAND_KEY_CAP]

            left, right = np.triu_indices(group.size, k=1)
            pair_chunks.append(np.stack([group[left], group[right]], axis=1))

    if not pair_chunks:
        return np.zeros((0, 2), dtype=np.int64)

    pairs = np.concatenate(pair_chunks, axis=0).astype(np.int64)

    # Normalise the ordering of each pair and remove duplicates.
    low = np.minimum(pairs[:, 0], pairs[:, 1])
    high = np.maximum(pairs[:, 0], pairs[:, 1])
    pairs = np.stack([low, high], axis=1)

    pairs = np.unique(pairs, axis=0)
    return pairs


def _filter_matches(pairs, hashes, positions, block_size, threshold, informative=None):
    """Keep only the pairs that really match and do not simply overlap."""
    if pairs.shape[0] == 0:
        return []

    if informative is not None:
        pairs = pairs[informative[pairs[:, 0]] & informative[pairs[:, 1]]]
        if pairs.shape[0] == 0:
            return []

    distances = np.bitwise_count(
        hashes[pairs[:, 0]] ^ hashes[pairs[:, 1]]
    ).astype(np.int32)

    keep = distances <= threshold
    pairs = pairs[keep]
    distances = distances[keep]

    if pairs.shape[0] == 0:
        return []

    # Blocks that overlap are neighbours in the picture, not copies.
    delta = np.abs(positions[pairs[:, 0]] - positions[pairs[:, 1]])
    overlap = (delta[:, 0] < block_size) & (delta[:, 1] < block_size)
    pairs = pairs[~overlap]
    distances = distances[~overlap]

    if pairs.shape[0] == 0:
        return []

    # Keep the strongest matches when there are more than the cap.
    if pairs.shape[0] > MATCH_CAP:
        strongest = np.argsort(distances, kind="stable")[:MATCH_CAP]
        pairs = pairs[strongest]
        distances = distances[strongest]

    matches = []
    for (index, other), distance in zip(pairs, distances):
        x1, y1 = positions[index]
        x2, y2 = positions[other]
        matches.append({
            "source": {"x": int(x1), "y": int(y1), "width": block_size, "height": block_size},
            "copy": {"x": int(x2), "y": int(y2), "width": block_size, "height": block_size},
            "hamming_distance": int(distance),
            "offset": {"dx": int(x2 - x1), "dy": int(y2 - y1)},
        })

    return matches


def _cluster_matches(matches, block_size, scale):
    """Merge overlapping matches into distinct duplicated regions."""
    if not matches:
        return []

    # Each match occupies two rectangles in the frame.
    rect_x1 = np.array(
        [min(m["source"]["x"], m["copy"]["x"]) for m in matches], dtype=np.int32
    )
    rect_y1 = np.array(
        [min(m["source"]["y"], m["copy"]["y"]) for m in matches], dtype=np.int32
    )
    rect_x2 = np.array(
        [max(m["source"]["x"], m["copy"]["x"]) + block_size for m in matches],
        dtype=np.int32,
    )
    rect_y2 = np.array(
        [max(m["source"]["y"], m["copy"]["y"]) + block_size for m in matches],
        dtype=np.int32,
    )

    # Connected components over the "these matches overlap" relation.
    groups = _connected_components(rect_x1, rect_y1, rect_x2, rect_y2)

    regions = []
    for label in np.unique(groups):
        members = np.flatnonzero(groups == label)

        min_x = int(rect_x1[members].min())
        min_y = int(rect_y1[members].min())
        max_x = int(rect_x2[members].max())
        max_y = int(rect_y2[members].max())

        regions.append({
            "source": {"x": min_x, "y": min_y, "width": max_x - min_x,
                       "height": max_y - min_y},
            "copy": {"x": min_x, "y": min_y, "width": max_x - min_x,
                     "height": max_y - min_y},
            "width": max_x - min_x,
            "height": max_y - min_y,
            "x": int(min_x * scale),
            "y": int(min_y * scale),
            "area_pixels": int((max_x - min_x) * (max_y - min_y) * scale * scale),
            "match_count": int(members.size),
        })

    regions.sort(key=lambda region: region["area_pixels"], reverse=True)
    return regions[:15]


def _connected_components(x1, y1, x2, y2):
    """Group rectangles into connected components by overlap."""
    count = x1.size

    try:
        from scipy.sparse import coo_matrix
        from scipy.sparse.csgraph import connected_components

        rows = []
        columns = []
        for index in range(count):
            overlap_x = (x1[index] < x2) & (x2[index] > x1)
            overlap_y = (y1[index] < y2) & (y2[index] > y1)
            neighbours = np.flatnonzero(overlap_x & overlap_y)
            rows.extend([index] * neighbours.size)
            columns.extend(neighbours.tolist())

        matrix = coo_matrix(
            (np.ones(len(rows), dtype=np.int8), (rows, columns)),
            shape=(count, count),
        ).tocsr()

        _, labels = connected_components(matrix, directed=False)
        return labels

    except ImportError:  # pragma: no cover - fallback path
        parent = list(range(count))

        def find(node):
            while parent[node] != node:
                parent[node] = parent[parent[node]]
                node = parent[node]
            return node

        for index in range(count):
            overlap_x = (x1[index] < x2) & (x2[index] > x1)
            overlap_y = (y1[index] < y2) & (y2[index] > y1)
            for other in np.flatnonzero(overlap_x & overlap_y):
                root_a, root_b = find(index), find(int(other))
                if root_a != root_b:
                    parent[root_b] = root_a

        labels = np.zeros(count, dtype=np.int64)
        for index in range(count):
            labels[index] = find(index)
        return labels
