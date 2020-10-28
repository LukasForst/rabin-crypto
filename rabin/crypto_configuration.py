# given by the assignment
# https://blackboard.au.dk/webapps/assignment/uploadAssignment?content_id=_2832837_1&course_id=_136793_1&group_id=&mode=view

TARGET_SECURITY_LEVEL_BITS = 128
PRIME_LENGTH_BITS = 1536
# m < n and as |n| = |p| + |q|
MAX_ENCRYPTED_BITS = (PRIME_LENGTH_BITS * 2) - 1

# must be smaller then MAX_ENCRYPTED_BITS // 8
# arbitrary selected as 256 bytes
PLAINTEXT_BLOCK_SIZE_BYTES = 256
# encrypting 256 bytes result in 384 cipher text bytes
CIPHERTEXT_BLOCK_SIZE_BYTES = PLAINTEXT_BLOCK_SIZE_BYTES + 128
