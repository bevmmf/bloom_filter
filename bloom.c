#include <assert.h>
#include <math.h>
#include <stdbool.h>
#include <string.h>
#include <stdbool.h>
#include "bloom.h"

/** Perform a safe cast to a uint32_t pointer
 *
 * The size of the byte slice is checked to be a multiple of `sizeof(uint32_t)`
 * using `assert()`. The slice gets done in way that is conformant with the
 * C strict-aliasing rules.
 *
 * \param slice The byte slice that should be cast
 * \returns The uint32_t pointer pointing at the beginning of the byte slice
 * \ingroup byte_slice
 */
static inline uint32_t *byte_slice_as_uint32_ptr(byte_slice_t slice)
{
    assert(slice.len % sizeof(uint32_t) == 0);
    union {
        uint8_t *bytes;
        uint32_t *ints;
    } aliasing_safe_cast;

    aliasing_safe_cast.bytes = slice.bytes;
    return aliasing_safe_cast.ints;
}

/** Set a bit to 1 in the byte slice
 *
 * \param set The byte slice to set the bit in
 * \param idx The index of the bit that should be set to 1
 * \ingroup byte_slice
 */
static inline void byte_slice_set_bit(byte_slice_t slice, size_t bit)
{
    assert(slice.len > (bit >> 3));
    slice.bytes[bit >> 3] |= 1 << (bit & 7);
}

/** Set a number of bits to 1 in the byte slice
 *
 * \param set      The byte slice to set the bit in
 * \param bits     The start of sequence of bit indexes for which the bit should
 * be set to 1 \param bits_len The number of bit indexes in the sequence
 * \ingroup byte_slice
 */
static inline void byte_slice_set_bits(byte_slice_t slice,
                                       size_t *bits,
                                       size_t bits_len)
{
    for (size_t i = 0; i < bits_len; i++)
        byte_slice_set_bit(slice, bits[i]);
}

/** Check if bit in the byte slice is set to 1
 *
 * \param set The byte slice to check the bit in
 * \param idx The index of the bit that should be checked
 * \ingroup byte_slice
 */
static inline bool byte_slice_bit_is_set(const byte_slice_t slice, size_t bit)
{
    assert(slice.len > (bit >> 3));
    return (slice.bytes[bit >> 3] & (1 << (bit & 7))) != 0;
}

/** Check if all of a number of bits are set in a byte slice
 *
 * \param set      The byte slice to set the bit in
 * \param bits     The start of sequence of bit indexes for which the bit should
 * be 1 \param bits_len The number of bit indexes in the sequence \ingroup
 * byte_slice
 */
static inline bool byte_slice_all_bits_set(const byte_slice_t slice,
                                           size_t *bits,
                                           size_t bits_len)
{
    for (size_t i = 0; i < bits_len; i++)
        if (!byte_slice_bit_is_set(slice, bits[i]))
            return false;
    return true;
}

static inline uint32_t byte_slice_mul32(byte_slice_t slice, uint32_t multiplier)
{
    assert(slice.len % sizeof(uint32_t) == 0);
    uint32_t *data = (uint32_t *) slice.bytes;
    uint32_t *end = data + (slice.len >> 2);
    uint32_t overflow = 0;
    while (data != end) {
        uint64_t tmp = ((uint64_t) *data) * ((uint64_t) multiplier);
        uint32_t mul_lo = tmp;
        uint32_t mul_hi = tmp >> 32;

        tmp = ((uint64_t) mul_lo) + ((uint64_t) overflow);
        if (tmp > ((uint32_t) 0xffffffffu)) /* check for overflow */
            mul_hi++;

        *data = tmp;
        overflow = mul_hi;
        data++;
    }
    return overflow;
}

void bloom_determine_offsets(size_t *bit_offsets,
                             size_t bit_offsets_len,
                             size_t filtersize,
                             const byte_slice_t input_hash)
{
    assert(filtersize >= 1 && filtersize < (1 << 29));
    assert(bit_offsets_len >= 1);
    assert(input_hash.len > 0);

    memset(bit_offsets, 0, sizeof(size_t) * bit_offsets_len);

    /* Copy input hash to stack (does not clobber 'input_hash' and allows the
     * compiler to see there is no aliasing).
     */
    uint8_t hash[input_hash.len];
    memcpy(hash, input_hash.bytes, input_hash.len);
    byte_slice_t hash_slice = byte_slice(hash, input_hash.len);

    size_t bs = filtersize << 3;  // number of bits in filter
    size_t num_bits = bit_offsets_len > bs ? bs : bit_offsets_len;

    assert(hash_slice.len % sizeof(uint32_t) == 0);
    for (size_t j = num_bits; j > 0; j--) {
        uint32_t overflow = byte_slice_mul32(hash_slice, bs);

        /* if we lost some entropy, re-add it
         * gcd(bs, 2 ** (32 * hashsize)) = 2 ** lost_bits
         * (e.g. if bs is odd, lost_bits is 1)
         */
        assert(sizeof(int) == sizeof(uint32_t));
        int lost_bits = ffs(bs);
        if (lost_bits > 1) {
            /* lost_bits is in [2..32], bit-shift is ok */
            uint32_t mask = (1 << (lost_bits - 1)) - 1;
            byte_slice_as_uint32_ptr(hash_slice)[0] += overflow & mask;
        }

        /* insert new value into bit_offsets[] */
        size_t i = j - 1;
        uint32_t _new = overflow;
        while (i + 1 < num_bits && _new >= bit_offsets[i + 1]) {
            bit_offsets[i] = bit_offsets[i + 1];
            i++;
            _new++;
        }
        bit_offsets[i] = _new;
        bs--;
    }
}

void bloom_set(byte_slice_t filter, const byte_slice_t hash, size_t num_bits)
{
    size_t bit_offsets[num_bits];
    bloom_determine_offsets(bit_offsets, num_bits, filter.len, hash);
    byte_slice_set_bits(filter, bit_offsets, num_bits);
}

bool bloom_is_set(const byte_slice_t filter,
                  const byte_slice_t hash,
                  size_t num_bits)
{
    size_t bit_offsets[num_bits];
    bloom_determine_offsets(bit_offsets, num_bits, filter.len, hash);
    return byte_slice_all_bits_set(filter, bit_offsets, num_bits);
}

/* FIXME: adjust for architecture features.
 * __builtin_popcount is assumed to be available.
 * Provide fallback implementation of 'popcount' if not available.
 */
typedef uint32_t popcount_t;
#define popcount __builtin_popcount

#define opt_align_begin(value, type) \
    ((uint8_t *) ((((size_t) value) + sizeof(type) - 1) & ~(sizeof(type) - 1)))
#define opt_align_end(value, type) \
    ((type *) (((size_t) value) & ~(sizeof(type) - 1)))

size_t bloom_nr_bits_set(const byte_slice_t filter)
{
    assert(filter.len <= (SIZE_MAX >> 3));
    const uint8_t *end = filter.bytes + filter.len;
    size_t bits = 0;

    union {
        const uint8_t *bytes;
        const popcount_t *opt;
    } cur = {filter.bytes};

    if (filter.len > sizeof(popcount_t) * 2) {
        /* Determine the beginning and end of the optimally aligned data */
        const uint8_t *opt_begin = opt_align_begin(filter.bytes, popcount_t);
        const popcount_t *opt_end = opt_align_end(end, popcount_t);

        /* Count bits in bytes until we reach the beginning of optimally
         * aligned data.
         */
        while (cur.bytes < opt_begin)
            bits += popcount(*cur.bytes++);

        /* Count as many optimally aligned bigger integers as possible */
        while (cur.opt < opt_end)
            bits += popcount(*cur.opt++);
    }

    /* Count bits in remaining bytes until the end */
    while (cur.bytes < end)
        bits += popcount(*cur.bytes++);

    return bits;
}

uint32_t bloom_approx_count(size_t filtersize, size_t k, size_t X)
{
    double m = filtersize << 3;
    if (m == X) {
        /* this would otherwise produce 0 due to casting of the double value
         * which should approximate infinity.
         */
        return UINT32_MAX;
    }
    /* Based on:
     * https://en.wikipedia.org/wiki/Bloom_filter#Approximating_the_number_of_items_in_a_Bloom_filter
     */
    return (uint32_t) roundl(-(m / k) * log(1 - ((double)X / m)));
}
