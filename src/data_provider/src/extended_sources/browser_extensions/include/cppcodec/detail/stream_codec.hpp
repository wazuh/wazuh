/**
 *  Copyright (C) 2015 Topology LP
 *  Copyright (C) 2018 Jakob Petsovits
 *  All rights reserved.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to
 *  deal in the Software without restriction, including without limitation the
 *  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 *  sell copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 *  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 *  IN THE SOFTWARE.
 */

#ifndef CPPCODEC_DETAIL_STREAM_CODEC
#define CPPCODEC_DETAIL_STREAM_CODEC

#include <limits>
#include <stdlib.h> // for abort()
#include <stdint.h>

#include "../parse_error.hpp"
#include "config.hpp"

namespace cppcodec
{
    namespace detail
    {

        using alphabet_index_t = uint_fast16_t;

        template <typename Codec, typename CodecVariant>
        class stream_codec
        {
            public:
                template <typename Result, typename ResultState> static void encode(
                    Result& encoded_result, ResultState&, const uint8_t* binary, size_t binary_size);

                template <typename Result, typename ResultState> static void decode(
                    Result& binary_result, ResultState&, const char* encoded, size_t encoded_size);

                static constexpr size_t encoded_size(size_t binary_size) noexcept;
                static constexpr size_t decoded_max_size(size_t encoded_size) noexcept;
        };

        template <bool GeneratesPadding> // default for CodecVariant::generates_padding() == false
        struct padder
        {
            template <typename CodecVariant, typename Result, typename ResultState, typename SizeT>
            static CPPCODEC_ALWAYS_INLINE void pad(Result&, ResultState&, SizeT) { }
        };

        template<> // specialization for CodecVariant::generates_padding() == true
        struct padder<true>
        {
            template <typename CodecVariant, typename Result, typename ResultState, typename SizeT>
            static CPPCODEC_ALWAYS_INLINE void pad(
                Result& encoded, ResultState& state, SizeT num_padding_characters)
            {
                for (SizeT i = 0; i < num_padding_characters; ++i)
                {
                    data::put(encoded, state, CodecVariant::padding_symbol());
                }
            }
        };

        template <size_t I>
        struct enc
        {
            // Block encoding: Go from 0 to (block size - 1), append a symbol for each iteration unconditionally.
            template <typename Codec, typename CodecVariant, typename Result, typename ResultState>
            static CPPCODEC_ALWAYS_INLINE void block(Result& encoded, ResultState& state, const uint8_t* src)
            {
                using EncodedBlockSizeT = decltype(Codec::encoded_block_size());
                constexpr static const EncodedBlockSizeT SymbolIndex = static_cast<EncodedBlockSizeT>(I - 1);

                enc < I - 1 > ().template block<Codec, CodecVariant>(encoded, state, src);
                data::put(encoded, state, CodecVariant::symbol(Codec::template index<SymbolIndex>(src)));
            }

            // Tail encoding: Go from 0 until (runtime) num_symbols, append a symbol for each iteration.
            template <typename Codec, typename CodecVariant, typename Result, typename ResultState,
                      typename EncodedBlockSizeT = decltype(Codec::encoded_block_size())>
            static CPPCODEC_ALWAYS_INLINE void tail(
                Result& encoded, ResultState& state, const uint8_t* src, EncodedBlockSizeT num_symbols)
            {
                constexpr static const EncodedBlockSizeT SymbolIndex = Codec::encoded_block_size() - I;
                constexpr static const EncodedBlockSizeT NumSymbols = SymbolIndex + static_cast<EncodedBlockSizeT>(1);

                if (num_symbols == NumSymbols)
                {
                    data::put(encoded, state, CodecVariant::symbol(Codec::template index_last<SymbolIndex>(src)));
                    return;
                }

                data::put(encoded, state, CodecVariant::symbol(Codec::template index<SymbolIndex>(src)));
                enc < I - 1 > ().template tail<Codec, CodecVariant>(encoded, state, src, num_symbols);
            }
        };

        template<> // terminating specialization
        struct enc<0>
        {
            template <typename Codec, typename CodecVariant, typename Result, typename ResultState>
            static CPPCODEC_ALWAYS_INLINE void block(Result&, ResultState&, const uint8_t*) { }

            template <typename Codec, typename CodecVariant, typename Result, typename ResultState,
                      typename EncodedBlockSizeT = decltype(Codec::encoded_block_size())>
            static CPPCODEC_ALWAYS_INLINE void tail(Result&, ResultState&, const uint8_t*, EncodedBlockSizeT)
            {
                abort(); // Not reached: block() should be called if num_symbols == block size, not tail().
            }
        };

        template <typename Codec, typename CodecVariant>
        template <typename Result, typename ResultState>
        inline void stream_codec<Codec, CodecVariant>::encode(
            Result& encoded_result, ResultState& state,
            const uint8_t* src, size_t src_size)
        {
            using encoder = enc<Codec::encoded_block_size()>;

            const uint8_t* src_end = src + src_size;

            if (src_size >= Codec::binary_block_size())
            {
                src_end -= Codec::binary_block_size();

                for (; src <= src_end; src += Codec::binary_block_size())
                {
                    encoder::template block<Codec, CodecVariant>(encoded_result, state, src);
                }

                src_end += Codec::binary_block_size();
            }

            if (src_end > src)
            {
                auto remaining_src_len = src_end - src;

                if (!remaining_src_len || remaining_src_len >= Codec::binary_block_size())
                {
                    abort();
                    return;
                }

                auto num_symbols = Codec::num_encoded_tail_symbols(
                                       static_cast<uint8_t>(remaining_src_len));

                encoder::template tail<Codec, CodecVariant>(encoded_result, state, src, num_symbols);

                padder<CodecVariant::generates_padding()>::template pad<CodecVariant>(
                    encoded_result, state, Codec::encoded_block_size() - num_symbols);
            }
        }

        // Range & lookup table generation, see
        // http://stackoverflow.com/questions/13313980/populate-an-array-using-constexpr-at-compile-time
        // and http://cplusadd.blogspot.ca/2013/02/c11-compile-time-lookup-tablearray-with.html

        template<unsigned... Is> struct seq {};

        template<unsigned N, unsigned... Is>
        struct gen_seq : gen_seq < N - 4, N - 4, N - 3, N - 2, N - 1, Is... >
        {
            // Clang up to 3.6 has a limit of 256 for template recursion,
            // so pass a few more symbols at once to make it work.
            static_assert(N % 4 == 0, "I must be divisible by 4 to eventually end at 0");
        };
        template<unsigned... Is>
        struct gen_seq<0, Is...> : seq<Is...> {};

        template <size_t N>
        struct lookup_table_t
        {
            alphabet_index_t lookup[N];
            static constexpr size_t size = N;
        };

        template<typename LambdaType, unsigned... Is>
        constexpr lookup_table_t<sizeof...(Is)> make_lookup_table(seq<Is...>, LambdaType value_for_index)
        {
            return { { value_for_index(Is)... } };
        }

        template<unsigned N, typename LambdaType>
        constexpr lookup_table_t<N> make_lookup_table(LambdaType evalFunc)
        {
            return make_lookup_table(gen_seq<N>(), evalFunc);
        }

        // CodecVariant::symbol() provides a symbol for an index.
        // Use recursive templates to get the inverse lookup table for fast decoding.

        template <typename T>
        static CPPCODEC_ALWAYS_INLINE constexpr size_t num_possible_values()
        {
            return static_cast<size_t>(
                       static_cast<intmax_t>((std::numeric_limits<T>::max)())
                       - static_cast<intmax_t>((std::numeric_limits<T>::min)()) + 1);
        }

        template <typename CodecVariant, alphabet_index_t InvalidIdx, size_t I>
        struct index_if_in_alphabet
        {
            static CPPCODEC_ALWAYS_INLINE constexpr alphabet_index_t for_symbol(char symbol)
            {
                return (CodecVariant::symbol(
                            static_cast<alphabet_index_t>(CodecVariant::alphabet_size() - I)) == symbol)
                       ? static_cast<alphabet_index_t>(CodecVariant::alphabet_size() - I)
                       : index_if_in_alphabet < CodecVariant, InvalidIdx, I - 1 >::for_symbol(symbol);
            }
        };
        template <typename CodecVariant, alphabet_index_t InvalidIdx>
        struct index_if_in_alphabet<CodecVariant, InvalidIdx, 0>   // terminating specialization
        {
            static CPPCODEC_ALWAYS_INLINE constexpr alphabet_index_t for_symbol(char)
            {
                return InvalidIdx;
            }
        };

        template <typename CodecVariant, size_t I>
        struct padding_searcher
        {
            static CPPCODEC_ALWAYS_INLINE constexpr bool exists_padding_symbol()
            {
                // Clang up to 3.6 has a limit of 256 for template recursion,
                // so pass a few more symbols at once to make it work.
                static_assert(I % 4 == 0, "I must be divisible by 4 to eventually end at 0");

                return CodecVariant::is_padding_symbol(
                           static_cast<char>(num_possible_values<char>() - I - 4))
                       || CodecVariant::is_padding_symbol(
                           static_cast<char>(num_possible_values<char>() - I - 3))
                       || CodecVariant::is_padding_symbol(
                           static_cast<char>(num_possible_values<char>() - I - 2))
                       || CodecVariant::is_padding_symbol(
                           static_cast<char>(num_possible_values<char>() - I - 1))
                       || padding_searcher < CodecVariant, I - 4 >::exists_padding_symbol();
            }
        };
        template <typename CodecVariant>
        struct padding_searcher<CodecVariant, 0>   // terminating specialization
        {
            static CPPCODEC_ALWAYS_INLINE constexpr bool exists_padding_symbol()
            {
                return false;
            }
        };

        template <typename CodecVariant>
        struct alphabet_index_info
        {
                static constexpr const size_t num_possible_symbols = num_possible_values<char>();

                static constexpr const alphabet_index_t padding_idx = 1 << 8;
                static constexpr const alphabet_index_t invalid_idx = 1 << 9;
                static constexpr const alphabet_index_t eof_idx = 1 << 10;
                static constexpr const alphabet_index_t stop_character_mask = static_cast<alphabet_index_t>(~0xFFu);

                static constexpr const bool padding_allowed = padding_searcher <
                                                              CodecVariant, num_possible_symbols >::exists_padding_symbol();

                static CPPCODEC_ALWAYS_INLINE constexpr bool allows_padding()
                {
                    return padding_allowed;
                }
                static CPPCODEC_ALWAYS_INLINE constexpr bool is_padding(alphabet_index_t idx)
                {
                    return allows_padding() ? (idx == padding_idx) : false;
                }
                static CPPCODEC_ALWAYS_INLINE constexpr bool is_invalid(alphabet_index_t idx)
                {
                    return idx == invalid_idx;
                }
                static CPPCODEC_ALWAYS_INLINE constexpr bool is_eof(alphabet_index_t idx)
                {
                    return idx == eof_idx;
                }
                static CPPCODEC_ALWAYS_INLINE constexpr bool is_stop_character(alphabet_index_t idx)
                {
                    return (idx & stop_character_mask) != 0;
                }

            private:
                static CPPCODEC_ALWAYS_INLINE constexpr
                alphabet_index_t valid_index_or(alphabet_index_t a, alphabet_index_t b)
                {
                    return a == invalid_idx ? b : a;
                }

                using idx_if_in_alphabet = index_if_in_alphabet <
                                           CodecVariant, invalid_idx, CodecVariant::alphabet_size() >;

                static CPPCODEC_ALWAYS_INLINE constexpr alphabet_index_t index_of(char symbol)
                {
                    return valid_index_or(idx_if_in_alphabet::for_symbol(symbol),
                                          CodecVariant::is_eof_symbol(symbol) ? eof_idx
                                          : CodecVariant::is_padding_symbol(symbol) ? padding_idx
                                          : invalid_idx);
                }

                // GCC <= 4.9 has a bug with retaining constexpr when passing a function pointer.
                // To get around this, we'll create a callable with operator() and pass that one.
                // Unfortunately, MSVC prior to VS 2017 (for MinSizeRel or Release builds)
                // chokes on this by compiling the project in 20 minutes instead of seconds.
                // So let's define two separate variants and remove the old GCC one whenever we
                // decide not to support GCC < 5.0 anymore.
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ < 5
                struct index_at
                {
                    CPPCODEC_ALWAYS_INLINE constexpr alphabet_index_t operator()(size_t symbol) const
                    {
                        return index_of(CodecVariant::normalized_symbol(static_cast<char>(symbol)));
                    }
                };
#else
                static CPPCODEC_ALWAYS_INLINE constexpr alphabet_index_t index_at(size_t symbol)
                {
                    return index_of(CodecVariant::normalized_symbol(static_cast<char>(symbol)));
                }
#endif

            public:
                struct lookup
                {
                    static CPPCODEC_ALWAYS_INLINE alphabet_index_t for_symbol(char symbol)
                    {
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ < 5
                        static constexpr const auto t = make_lookup_table<num_possible_symbols>(index_at());
#else
                        static constexpr const auto t = make_lookup_table<num_possible_symbols>(&index_at);
#endif
                        static_assert(t.size == num_possible_symbols,
                                      "lookup table must cover each possible (character) symbol");
                        return t.lookup[static_cast<uint8_t>(symbol)];
                    }
                };
        };

        //
        // At long last! The actual decode/encode functions.

        template <typename Codec, typename CodecVariant>
        template <typename Result, typename ResultState>
        inline void stream_codec<Codec, CodecVariant>::decode(
            Result& binary_result, ResultState& state,
            const char* src_encoded, size_t src_size)
        {
            using alphabet_index_lookup = typename alphabet_index_info<CodecVariant>::lookup;
            const char* src = src_encoded;
            const char* src_end = src + src_size;

            alphabet_index_t alphabet_indexes[Codec::encoded_block_size()] = {};
            alphabet_indexes[0] = alphabet_index_info<CodecVariant>::eof_idx;

            alphabet_index_t* const alphabet_index_start = &alphabet_indexes[0];
            alphabet_index_t* const alphabet_index_end = &alphabet_indexes[Codec::encoded_block_size()];
            alphabet_index_t* alphabet_index_ptr = &alphabet_indexes[0];

            while (src < src_end)
            {
                if (CodecVariant::should_ignore(*src))
                {
                    ++src;
                    continue;
                }

                *alphabet_index_ptr = alphabet_index_lookup::for_symbol(*src);

                if (alphabet_index_info<CodecVariant>::is_stop_character(*alphabet_index_ptr))
                {
                    break;
                }

                ++src;
                ++alphabet_index_ptr;

                if (alphabet_index_ptr == alphabet_index_end)
                {
                    Codec::decode_block(binary_result, state, alphabet_indexes);
                    alphabet_index_ptr = alphabet_index_start;
                }
            }

            if (alphabet_index_info<CodecVariant>::is_invalid(*alphabet_index_ptr))
            {
                throw symbol_error(*src);
            }

            ++src;

            alphabet_index_t* last_index_ptr = alphabet_index_ptr;

            if (alphabet_index_info<CodecVariant>::is_padding(*last_index_ptr))
            {
                if (last_index_ptr == alphabet_index_start)
                {
                    // Don't accept padding at the start of a block.
                    // The encoder should have omitted that padding altogether.
                    throw padding_error();
                }

                // We're in here because we just read a (first) padding character. Try to read more.
                // Count with last_index_ptr, but store in alphabet_index_ptr so we don't
                // overflow the array in case the input data is too long.
                ++last_index_ptr;

                while (src < src_end)
                {
                    *alphabet_index_ptr = alphabet_index_lookup::for_symbol(*(src++));

                    if (alphabet_index_info<CodecVariant>::is_eof(*alphabet_index_ptr))
                    {
                        *alphabet_index_ptr = alphabet_index_info<CodecVariant>::padding_idx;
                        break;
                    }

                    if (!alphabet_index_info<CodecVariant>::is_padding(*alphabet_index_ptr))
                    {
                        throw padding_error();
                    }

                    ++last_index_ptr;

                    if (last_index_ptr > alphabet_index_end)
                    {
                        throw padding_error();
                    }
                }
            }

            if (last_index_ptr != alphabet_index_start)
            {
                if ((CodecVariant::requires_padding()
                        || alphabet_index_info<CodecVariant>::is_padding(*alphabet_index_ptr)
                    ) && last_index_ptr != alphabet_index_end)
                {
                    // If the input is not a multiple of the block size then the input is incorrect.
                    throw padding_error();
                }

                if (alphabet_index_ptr >= alphabet_index_end)
                {
                    abort();
                    return;
                }

                Codec::decode_tail(binary_result, state, alphabet_indexes,
                                   static_cast<size_t>(alphabet_index_ptr - alphabet_index_start));
            }
        }

        template <typename Codec, typename CodecVariant>
        inline constexpr size_t stream_codec<Codec, CodecVariant>::encoded_size(size_t binary_size) noexcept
        {
            using C = Codec;

            // constexpr rules make this a lot harder to read than it actually is.
            return CodecVariant::generates_padding()
                   // With padding, the encoded size is a multiple of the encoded block size.
                   // To calculate that, round the binary size up to multiple of the binary block size,
                   // then convert to encoded by multiplying with { base32: 8/5, base64: 4/3 }.
                   ? (binary_size + (C::binary_block_size() - 1)
                      - ((binary_size + (C::binary_block_size() - 1)) % C::binary_block_size()))
                   * C::encoded_block_size() / C::binary_block_size()
                   // No padding: only pad to the next multiple of 5 bits, i.e. at most a single extra byte.
                   : (binary_size * C::encoded_block_size() / C::binary_block_size())
                   + (((binary_size * C::encoded_block_size()) % C::binary_block_size()) ? 1 : 0);
        }

        template <typename Codec, typename CodecVariant>
        inline constexpr size_t stream_codec<Codec, CodecVariant>::decoded_max_size(size_t encoded_size) noexcept
        {
            using C = Codec;

            return CodecVariant::requires_padding()
                   ? (encoded_size / C::encoded_block_size() * C::binary_block_size())
                   : (encoded_size / C::encoded_block_size() * C::binary_block_size())
                   + ((encoded_size % C::encoded_block_size())
                      * C::binary_block_size() / C::encoded_block_size());
        }

    } // namespace detail
} // namespace cppcodec

#endif // CPPCODEC_DETAIL_STREAM_CODEC
