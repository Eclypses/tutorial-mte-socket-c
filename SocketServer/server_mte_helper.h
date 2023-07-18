/*
THIS SOFTWARE MAY NOT BE USED FOR PRODUCTION. Otherwise,
The MIT License (MIT)

Copyright (c) Eclypses, Inc.

All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#ifndef server_mte_helper_h
#define server_mte_helper_h

#include "globals.h"
#include "socket_manager.h"
#include "mte_alloca.h"
#include "mte_base.h"
#include "mte_base64.h"
#include "mte_dec.h"
#include "mte_enc.h"
#include "mte_init.h"
#include "mte_license.h"
#include "mte_status.h"
#include "mtesupport_ecdh.h"
#if defined USE_MTE_CORE
#endif
#if defined USE_MKE_ADDON
#    include "mte_mke_enc.h"
#    include "mte_mke_dec.h"
#endif
#if defined USE_FLEN_ADDON
#    include "mte_flen_enc.h"
#    include "mte_dec.h"
#endif

#ifdef __cplusplus
extern "C"
{
#endif

  struct mte_setup_info
  {
    // The personalization string.
    byte_array personalization;
    // The nonce.
    byte_array nonce;
    // This entity's public key.
    uint8_t my_public_key[SZ_ECDH_P256_PUBLIC_KEY];
    byte_array public_key;
    // The public key received from its peer.
    uint8_t my_peer_public_key[SZ_ECDH_P256_PUBLIC_KEY];
    byte_array peer_public_key;
    // This entity's private key [DO NOT SHARE].
    uint8_t my_private_key[SZ_ECDH_P256_PRIVATE_KEY];
    byte_array private_key;
  };

  /// <summary>
  /// Initialize the MTE, including the MTE itself, the license, and the randomizer.
  /// </summary>
  /// <returns>True if MTE is initialized properly, false otherwise.</returns>
  const bool init_mte();

  /// <summary>
  /// Creates the Encoder.
  /// </summary>
  /// <returns>True if the Encoder was created successfully.</returns>
  bool create_encoder();

  /// <summary>
  /// Creates the Decoder.
  /// </summary>
  /// <returns>True if the Decoder was created successfully.</returns>
  bool create_decoder();

  /// <summary>
  /// Encodes the given message with the MTE. * Note that the caller must
  /// run a "free(*encoded)" after processing the result. Otherwise a
  /// memory leak will occur!
  /// </summary>
  /// <param name="message">The message to be encoded.</param>
  /// <param name="encoded">The encoded message.</param>
  /// <param name="encoded_bytes">The size of the encoded message in bytes.</param>
  /// <returns>True if MTE encoded successfully.</returns>
  bool encode_message(const char* message, char** encoded, size_t* encoded_bytes);

  /// <summary>
  /// Decodes the given encoded message with the MTE. * Note that the caller must
  /// run a "free(*decoded_message)" after processing the result. Otherwise a
  /// memory leak will occur!
  /// </summary>
  /// <param name="encoded">The encoded message.</param>
  /// <param name="encoded_bytes">The size of the encoded message in bytes.</param>
  /// <param name="decoded_message">The decoded message.</param>
  /// <returns>True if MTE decoded successfully.</returns>
  bool decode_message(char* encoded, size_t encoded_bytes, char** decoded_message);

  /// <summary>
  /// Finalizes the Encoder and Decoder.
  /// </summary>
  void finish_mte();

  /// <summary>
  /// Exchanges the information needed between the client and server for MTE setup.
  /// </summary>
  /// <returns>True if the information was exchanged successfully.</returns>
  static bool exchange_mte_info();

  /// <summary>
  /// The callback function for the Encoder's entropy input.
  /// </summary>
  /// <returns>MTE status of the callback function.</returns>
  static mte_status encoder_entropy_input_callback(const void* context, mte_drbg_ei_info* info);

  /// <summary>
  /// The callback function for the Decoder's entropy input.
  /// </summary>
  /// <returns>MTE status of the callback function.</returns>
  static mte_status decoder_entropy_input_callback(const void* context, mte_drbg_ei_info* info);

  /// <summary>
  /// The callback function for the Encoder's nonce.
  /// </summary>
  static void encoder_nonce_callback(const void* context, mte_drbg_nonce_info* info);

  /// <summary>
  /// The callback function for the Decoder's nonce.
  /// </summary>
  static void decoder_nonce_callback(const void* context, mte_drbg_nonce_info* info);

  /// <summary>
 /// The callback function for the Encoder's timestamp.
 /// </summary>
 /// <returns>The timestamp.</returns>
  static uint64_t encoder_timestamp_callback(const void* context);

  /// <summary>
  /// The callback function for the Decoder's timestamp.
  /// </summary>
  /// <returns>The timestamp.</returns>
  static uint64_t decoder_timestamp_callback(const void* context);

  /// <summary>
  /// Gets the current timestamp.
  /// </summary>
  /// <returns>The timestamp.</returns>
  static uint64_t get_timestamp();

  /// <summary>
  /// Convert a byte array to an ASCII hex representation.
  /// </summary>
  /// <param name="in">Pointer to the input byte array.</param>
  /// <param name="insz">The size of the input byte array in bytes.</param>
  /// <returns>Pointer to the output byte array.</returns>
  static char* bytes_to_hex(const uint8_t* in, size_t insz);

  /// <summary>
  /// Displays the message in base 64.
  /// </summary>
  /// <param name="message">The message to be displayed.</param>
  /// <param name="message_bytes">The size of the message in bytes.</param>
  static void display_message_base64(const uint8_t* message, size_t message_bytes);

  /// <summary>
  /// Displays the message in an ASCII hex representation.
  /// </summary>
  /// <param name="message">The message to be displayed.</param>
  /// <param name="message_bytes">The size of the message in bytes.</param>
  static void display_message_hex(const uint8_t* message, size_t message_bytes);

  /// <summary>
  /// Displays the message in base 64 and ASCII hex representation.
  /// </summary>
  /// <param name="message">The message to be displayed.</param>
  /// <param name="message_bytes">The size of the message in bytes.</param>
  void display_message_all(const uint8_t* message, size_t message_bytes);

  /// <summary>
    /// Creates a byte array using the given size in bytes. The data will be set to an array
    /// based on the size, or null if size if zero.
    /// </summary>
    /// <param name="size">The size of the data in bytes.</param>
    /// <returns>An empty byte array with the given size (or null if size of zero).</returns>
  static byte_array create_byte_array_size(size_t size);

  /// <summary>
  /// Creates a copy of the source byte array.
  /// </summary>
  /// <param name="source">The byte array to be copied.</param>
  /// <returns>The copied byte array.</returns>
  static byte_array create_byte_array(const byte_array source);

  /// <summary>
  /// Creates a byte array with the given data and size.
  /// </summary>
  /// <param name="source">The pointer to the source data.</param>
  /// <param name="size">The size of the data.</param>
  /// <returns>A byte array pointing to the source data.</returns>
  static byte_array create_byte_array_pointer(uint8_t* source, size_t size);

#ifdef __cplusplus
}
#endif

#endif