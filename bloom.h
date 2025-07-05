/* Bloom filter - a space-efficient probabilistic data structure */

#ifndef BLOOM_H
#define BLOOM_H

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
/* This structure represents a sequence of bytes in memory.
 *
 * It is effectively a convenience type for working with uint8_t "pointer +
 * length" and some auxiliary functions one might want to perform on such a
 * chunk of memory.
 *
 * This type is expected to be used "as is" and not through some pointer. One
 * could consider it to effectively be a "fat pointer".
 */
typedef struct {
    uint8_t *bytes;
    size_t len;
} byte_slice_t;

/** Create a byte slice
 *
 * This is a convenience function to simply create a `byte_slice_t` structure.
 *
 * \param bytes A pointer to the beginning of the sequence of bytes
 * \param len   The number of bytes the sequence is long
 * \returns An initialized `byte_slice_t` structure
 * \ingroup byte_slice
 */
static inline byte_slice_t byte_slice(void *bytes, size_t len)
{
    byte_slice_t slice = {(uint8_t *) bytes, len};
    return slice;
}

/** \def byte_slice_from_scalar
 *
 * This convenience method creates a `byte_slice_t` for a simple scalar
 * value.
 *
 * Example:
 *
 * ```c
 * int number = 13;
 * byte_slice_t number_slice = byte_slice_from_scalar(number);
 * assert(number_slice.len == sizeof(int));
 * ```
 *
 * \param value A scalar value
 * \returns An initialized `byte_slice_t` structure for that scalar value
 * \ingroup byte_slice
 */
#define byte_slice_from_scalar(value) \
    byte_slice((void *) &(value), sizeof(value))

/** \def byte_slice_from_array
 *
 * This convenience method creates a `byte_slice_t` for an array of scalar
 * values.
 *
 * Example:
 *
 * ```c
 * int numbers[4] = { 0 };
 * byte_slice_t numbers_slice = byte_slice_from_array(numbers);
 * assert(numbers_slice.len == sizeof(int) * 4);
 * ```
 *
 * \param value A scalar array
 * \returns An initialized `byte_slice_t` structure for that scalar array
 * \ingroup byte_slice
 */
#define byte_slice_from_array(value) byte_slice((void *) (value), sizeof(value))

/// \defgroup bloom Bloom filter operations

/** This file defines a number of bloom filter operations
 *
 * The functions operate on a byte slice that represent the bloom filter data.
 *
 * The user is responsible for supplying data using an appropriate hash
 * function, one that should at least have very good collision resistence.
 *
 * E.g. something like
 * [murmurhash3](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp)
 *
 * Fast hashes which can be used for bloom-filters can be found in the Wikipedia
 * article with a [list of hash
 * functions](https://en.wikipedia.org/wiki/List_of_hash_functions#Non-cryptographic_hash_functions)
 */

/** Add a hashed value to the bloom filter
 *
 * Add the `hash` of a value to the `filter` where `num_bits` of bits
 * should be set for each unique value.
 *
 * \warning The supplied hash length must be a multiple of `sizeof(uint32_t)`
 *
 * \param filter   The bloom filter to be updated
 * \param hash     The hash of the data that should be added
 * \param num_bits The number of bits that should be set for this item (aka: `k`
 * value) \ingroup bloom
 */
void bloom_set(byte_slice_t filter, const byte_slice_t hash, size_t num_bits);

/** Check if hashed value is probably present in the bloom filter
 *
 * Checks if the `hash` of a value is likely present in the `filter`
 * where `num_bits` of bits should be set for each unique value.
 *
 * \warning The supplied hash length must be a multiple of `sizeof(uint32_t)`
 *
 * \param filter   The bloom filter to be updated
 * \param hash     The hash of the data that should be added
 * \param num_bits The number of bits that should be set for this item (aka: `k`
 * value) \returns `true` if the hashed value is probably present, `false`
 * otherwise \ingroup bloom
 */
bool bloom_is_set(const byte_slice_t filter,
                  const byte_slice_t hash,
                  size_t num_bits);

/** Determine the number of bits set to 1
 *
 * \param filter The bloom filter to check
 * \returns The number of bits set to 1 in the bloom filter
 * \ingroup bloom
 */
size_t bloom_nr_bits_set(const byte_slice_t filter);

/** Determine approximate number of unique values present in a bloom filter
 *
 * \param filtersize The size in bytes of the bloom filter
 * \param num_bits   The number of bits that should be set for this item (aka:
 * `k` value) \param bits_set   The number of bits set to 1 in the bloom filter
 * \returns Approximate number of unique values in the filter.
 * \ingroup bloom
 */
uint32_t bloom_approx_count(size_t filtersize,
                            size_t num_bits,
                            size_t bits_set);

/** Determine which bits should be set to 1 in a bloom filter for some hashed
 * value
 *
 * This function is used to determine which offsets should be set for a given
 * hash. (it's mainly exposed for unittest purposes)
 *
 * \param bit_offsets     A sequence of bit indexes that will be updated to
 * indicate which bits should be set \param bit_offsets_len The number of bit
 * indexes that that should be filled (aka: the `k` value of the bloom filter)
 * \param filtersize      The size in bytes of the bloom filter
 * \param input_hash      The hash of the data for which to determine the bit
 * indexes \ingroup bloom \private
 */
void bloom_determine_offsets(size_t *bit_offsets,
                             size_t bit_offsets_len,
                             size_t filtersize,
                             const byte_slice_t input_hash);

#endif /* BLOOM_H */