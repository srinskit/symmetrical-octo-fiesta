#include <gcrypt.h>

unsigned mine(const unsigned char *challenge,
              unsigned challenge_len,
              unsigned char *nonce,
              unsigned nonce_len,
              const unsigned char target[32],
              unsigned limit) {
    const unsigned target_bits = 256;
    const unsigned target_len = target_bits / 8;
    gcry_mpi_t mpi_target = gcry_mpi_new(target_bits);
    gcry_mpi_scan(&mpi_target, GCRYMPI_FMT_USG, target, target_len, nullptr);

    unsigned msg_len = challenge_len + nonce_len;
    auto msg = new unsigned char[msg_len];
    auto nonce_start = msg + challenge_len;
    memcpy(msg, challenge, challenge_len);

    gcry_mpi_t mpi_digest;
    unsigned char digest[target_len];
    unsigned i = limit;
    bool unlimited = limit == 0, res;
    while (unlimited || i) {
        gcry_create_nonce(nonce_start, nonce_len);
        gcry_md_hash_buffer(GCRY_MD_SHA256, digest, msg, msg_len);
        gcry_mpi_scan(&mpi_digest, GCRYMPI_FMT_USG, digest, target_len, nullptr);
        res = gcry_mpi_cmp(mpi_digest, mpi_target) <= 0;
        gcry_mpi_release(mpi_digest);

        if (res)
            break;
        if (!unlimited)
            i--;
    }
    if (unlimited || i)
        memcpy(nonce, nonce_start, nonce_len);

    gcry_mpi_release(mpi_target);
    delete[] msg;

    return i;
}

unsigned verify(const unsigned char *challenge,
                unsigned challenge_len,
                unsigned char *nonce,
                unsigned nonce_len,
                const unsigned char target[32]) {
    const unsigned target_bits = 256;
    const unsigned target_len = target_bits / 8;
    gcry_mpi_t mpi_target = gcry_mpi_new(target_bits);
    gcry_mpi_scan(&mpi_target, GCRYMPI_FMT_USG, target, target_len, nullptr);

    unsigned msg_len = challenge_len + nonce_len;
    auto msg = new unsigned char[msg_len];
    auto nonce_start = msg + challenge_len;
    memcpy(msg, challenge, challenge_len);
    memcpy(nonce_start, nonce, nonce_len);

    gcry_mpi_t mpi_digest;
    unsigned char digest[target_len];
    gcry_md_hash_buffer(GCRY_MD_SHA256, digest, msg, msg_len);
    gcry_mpi_scan(&mpi_digest, GCRYMPI_FMT_USG, digest, target_len, nullptr);

    bool ret = gcry_mpi_cmp(mpi_digest, mpi_target) <= 0;

    gcry_mpi_release(mpi_digest);
    gcry_mpi_release(mpi_target);
    delete[] msg;

    return ret;
}

int main() {
    unsigned char challenge[] = {128};
    unsigned char nonce[10];
    unsigned char target[32] = {0, 0, 0, 128};
    printf("%d\n", mine(challenge, sizeof(challenge), nonce, sizeof(nonce), target, 0));
    printf("%d\n", verify(challenge, sizeof(challenge), nonce, sizeof(nonce), target));
    return 0;
}