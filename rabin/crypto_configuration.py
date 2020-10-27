# given by the assignment
# https://blackboard.au.dk/webapps/assignment/uploadAssignment?content_id=_2832837_1&course_id=_136793_1&group_id=&mode=view

TARGET_SECURITY_LEVEL_BITS = 128
PRIME_LENGTH_BITS = 1536
# m < n and as |n| = |p| + |q|
MAX_ENCRYPTED_BITS = (PRIME_LENGTH_BITS * 2) - 1

BLOCK_SIZE_BYTES = 256
