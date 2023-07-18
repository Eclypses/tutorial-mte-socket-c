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

#include "client_mte_helper.h"

static MTE_HANDLE encoder;
static mte_status encoder_status;

static MTE_HANDLE decoder;
static mte_status decoder_status;

// No timestamp or sequence windows will be used for the Decoder.
static const uint64_t timestamp_window = 0;
static const int32_t sequence_window = 0;

// Create the client Encoder and Decoder info structs.
// Client Encoder -> Server Decoder;
struct mte_setup_info client_encoder_info;
// Client Decoder <- Server Encoder;
struct mte_setup_info client_decoder_info;

const bool init_mte()
{
  // Initialize MTE.
  if (!mte_init(NULL, NULL))
  {
    printf("There was an error attempting to initialize the MTE.\n");
    return false;
  }

  // Initialize MTE license. If a license code is not required (e.g., trial
  // mode), this can be skipped.
  if (!mte_license_init("LicenseCompanyName", "LicenseKey"))
  {
    printf("There was an error attempting to initialize the MTE License.\n");
    return false;
  }

  // Exchange entropy, nonce, and personalization string between the client and server.
  if (!exchange_mte_info())
  {
    printf("There was an error attempting to exchange information between this and the client.\n");
    return false;
  }

  return true;
}

bool create_encoder()
{
  // Display all info related to the Encoder.
  printf("Client encoder public key:\n");
  display_message_all(client_encoder_info.my_public_key, SZ_ECDH_P256_PUBLIC_KEY);
  printf("Client encoder peer's key:\n");
  display_message_all(client_encoder_info.peer_public_key.data, SZ_ECDH_P256_PUBLIC_KEY);
  printf("Client encoder nonce:\n");
  display_message_all(client_encoder_info.nonce.data, client_encoder_info.nonce.size);
  printf("Client encoder personalization\n");
  display_message_all(client_encoder_info.personalization.data, client_encoder_info.personalization.size);

  // Create the Encoder with the default options.
#if defined USE_MTE_CORE  
  mte_enc_init_info encoder_info = MTE_ENC_INIT_INFO_INIT(
    MTE_DRBG_ENUM, MTE_TOKBYTES, MTE_VERIFIERS_ENUM, NULL, NULL);
  encoder = malloc(mte_enc_state_bytes(&encoder_info));

  // Initiate the Encoder state.
  encoder_status = mte_enc_state_init(encoder, &encoder_info);
#endif
#if defined USE_MKE_ADDON  
  mte_mke_enc_init_info encoder_info = MTE_MKE_ENC_INIT_INFO_INIT(
    MTE_DRBG_ENUM, MTE_TOKBYTES, MTE_VERIFIERS_ENUM, MTE_CIPHER_ENUM, MTE_HASH_ENUM, NULL, NULL, NULL, NULL, NULL, NULL);
  encoder = malloc(mte_mke_enc_state_bytes(&encoder_info));

  // Initiate the Encoder state.
  encoder_status = mte_mke_enc_state_init(encoder, &encoder_info);
#endif
#if defined USE_FLEN_ADDON
  uint32_t fixed_bytes = MAX_INPUT_BYTES;
  mte_flen_enc_init_info encoder_info = MTE_FLEN_ENC_INIT_INFO_INIT(
    MTE_DRBG_ENUM, MTE_TOKBYTES, MTE_VERIFIERS_ENUM, fixed_bytes, NULL, NULL);
  encoder = malloc(mte_flen_enc_state_bytes(&encoder_info));

  // Initiate the Encoder state.
  encoder_status = mte_flen_enc_state_init(encoder, &encoder_info);
#endif

  if (encoder_status != mte_status_success)
  {
    printf("Encoder init error (%s): %s\n",
      mte_base_status_name(encoder_status),
      mte_base_status_description(encoder_status));
    return false;
  }

  // Set the Encoder instantiation information.
  mte_drbg_inst_info enc_inst_info = { &encoder_entropy_input_callback, NULL, &encoder_nonce_callback, NULL, client_encoder_info.personalization.data, client_encoder_info.personalization.size };

  // Instantiate the Encoder.
#if defined USE_MTE_CORE
  encoder_status = mte_enc_instantiate(encoder, &enc_inst_info);
#endif
#if defined USE_MKE_ADDON
  encoder_status = mte_mke_enc_instantiate(encoder, &enc_inst_info);
#endif
#if defined USE_FLEN_ADDON
  encoder_status = mte_flen_enc_instantiate(encoder, &enc_inst_info);
#endif

  if (encoder_status != mte_status_success)
  {
    fprintf(stderr, "Encoder instantiate error (%s): %s\n",
      mte_base_status_name(encoder_status),
      mte_base_status_description(encoder_status));
    return false;
  }

  // Zeroize the personalization.
  ecdh_p256_zeroize(client_encoder_info.personalization.data, client_encoder_info.personalization.size);

  // Zeroize the private key.
  ecdh_p256_zeroize(client_encoder_info.my_private_key, SZ_ECDH_P256_PRIVATE_KEY);

  return true;
}

bool create_decoder()
{
  // Display all info related to the Decoder.
  printf("Client decoder public key:\n");
  display_message_all(client_decoder_info.my_public_key, SZ_ECDH_P256_PUBLIC_KEY);
  printf("Client decoder peer's key:\n");
  display_message_all(client_decoder_info.peer_public_key.data, SZ_ECDH_P256_PUBLIC_KEY);
  printf("Client decoder nonce:\n");
  display_message_all(client_decoder_info.nonce.data, client_decoder_info.nonce.size);
  printf("Client decoder personalization\n");
  display_message_all(client_decoder_info.personalization.data, client_decoder_info.personalization.size);

  // Create the Encoder with the default options.
#if defined USE_MTE_CORE   || defined USE_FLEN_ADDON
  mte_dec_init_info decoder_info = MTE_DEC_INIT_INFO_INIT(
    MTE_DRBG_ENUM, MTE_TOKBYTES, MTE_VERIFIERS_ENUM, timestamp_window, sequence_window, NULL, NULL);
  decoder = malloc(mte_dec_state_bytes(&decoder_info));

  // Initiate the Decoder state.
  decoder_status = mte_dec_state_init(decoder, &decoder_info);
#endif
#if defined USE_MKE_ADDON 
  mte_mke_dec_init_info decoder_info = MTE_MKE_DEC_INIT_INFO_INIT(
    MTE_DRBG_ENUM, MTE_TOKBYTES, MTE_VERIFIERS_ENUM, MTE_CIPHER_ENUM, MTE_HASH_ENUM, timestamp_window, sequence_window, NULL, NULL, NULL, NULL, NULL, NULL);
  decoder = malloc(mte_mke_dec_state_bytes(&decoder_info));

  // Initiate the Decoder state.
  decoder_status = mte_mke_dec_state_init(decoder, &decoder_info);
#endif

  if (decoder_status != mte_status_success)
  {
    printf("Decoder init error (%s): %s\n",
      mte_base_status_name(decoder_status),
      mte_base_status_description(decoder_status));
    return false;
  }

  // Set the Decoder instantiation information.
  mte_drbg_inst_info dec_inst_info = { &decoder_entropy_input_callback, NULL, &decoder_nonce_callback, NULL, client_decoder_info.personalization.data, client_decoder_info.personalization.size };

  // Instantiate the Decoder.
#if defined USE_MTE_CORE || defined USE_FLEN_ADDON
  decoder_status = mte_dec_instantiate(decoder, &dec_inst_info);
#endif
#if defined USE_MKE_ADDON
  decoder_status = mte_mke_dec_instantiate(decoder, &dec_inst_info);
#endif

  if (decoder_status != mte_status_success)
  {
    fprintf(stderr, "Decoder instantiate error (%s): %s\n",
      mte_base_status_name(decoder_status),
      mte_base_status_description(decoder_status));
    return false;
  }

  // Zeroize the personalization.
  ecdh_p256_zeroize(client_decoder_info.personalization.data, client_decoder_info.personalization.size);

  // Zeroize the private key.
  ecdh_p256_zeroize(client_decoder_info.my_private_key, SZ_ECDH_P256_PRIVATE_KEY);

  return true;
}

bool encode_message(const char* message, char** encoded, size_t* encoded_bytes)
{
  // Display original message.
  printf("\nMessage to be encoded: %s\n", message);

  // Get length of message.
  size_t message_bytes = strlen(message);

  // Encode the message.
#if defined USE_MTE_CORE
  /* Create local encoding buffer for MTE. */
  uint8_t* mte_buffer = MTE_ALLOCA(mte_enc_buff_bytes(encoder, message_bytes));
  mte_enc_args encoding_args = MTE_ENC_ARGS_INIT(NULL, 0, NULL, &encoder_timestamp_callback, NULL);
  MTE_SET_ENC_IO(encoding_args, message, message_bytes, mte_buffer);
  encoder_status = mte_enc_encode(encoder, &encoding_args);
#endif
#if defined USE_MKE_ADDON
  /* Create local encoding buffer for MTE. */
  uint8_t* mte_buffer = MTE_ALLOCA(mte_mke_enc_buff_bytes(encoder, message_bytes));
  mte_enc_args encoding_args = MTE_ENC_ARGS_INIT(NULL, 0, NULL, &encoder_timestamp_callback, NULL);
  MTE_SET_ENC_IO(encoding_args, message, message_bytes, mte_buffer);
  encoder_status = mte_mke_enc_encode(encoder, &encoding_args);
#endif
#if defined USE_FLEN_ADDON
  /* Create local encoding buffer for MTE. */
  uint8_t* mte_buffer = MTE_ALLOCA(mte_flen_enc_buff_bytes(encoder));
  mte_enc_args encoding_args = MTE_ENC_ARGS_INIT(NULL, 0, NULL, &encoder_timestamp_callback, NULL);
  MTE_SET_ENC_IO(encoding_args, message, message_bytes, mte_buffer);
  encoder_status = mte_flen_enc_encode(encoder, &encoding_args);
#endif

  // Ensure that it encoded successfully.
  if (encoder_status != mte_status_success)
  {
    fprintf(stderr, "Error encoding: Status: %s/%s\n",
      mte_base_status_name(encoder_status),
      mte_base_status_description(encoder_status));
    fprintf(stderr, "Socket client closed due to encoding error.\n");
    return false;
  }

  /* Setup the result count and buffer */
  *encoded_bytes = encoding_args.bytes;
  *encoded = malloc(encoding_args.bytes);
  if (encoding_args.encoded != 0)
  {
    memcpy(*encoded, encoding_args.encoded, *encoded_bytes);
  }

  // Display encoded message.
#if defined DISPLAY_HEX  || defined DISPLAY_B64
  printf("Encoded message being sent:\n");
  display_message_all(*encoded, *encoded_bytes);
#endif

  /*-----------------------------------------------------------
   * Note that the caller must run a "free(*encoded)" after
   * processing the result. Otherwise a memory leak will occur!
   *---------------------------------------------------------*/
  return true;
}

bool decode_message(char* encoded, size_t encoded_bytes, char** decoded_message)
{
  // Display encoded message.
#if defined DISPLAY_HEX|| defined DISPLAY_B64
  printf("\nEncoded message received:\n");
  display_message_all(encoded, encoded_bytes);
#endif

  // Decode the encoded message.
#if defined USE_MTE_CORE || defined USE_FLEN_ADDON
  uint8_t* mte_buffer = MTE_ALLOCA(mte_dec_buff_bytes(decoder, encoded_bytes));
  mte_dec_args decoding_args = MTE_DEC_ARGS_INIT(NULL, 0, NULL, &decoder_timestamp_callback, NULL);
  MTE_SET_DEC_IO(decoding_args, encoded, encoded_bytes, mte_buffer);
  decoder_status = mte_dec_decode(decoder, &decoding_args);
#endif
#if defined USE_MKE_ADDON
  uint8_t* mte_buffer = MTE_ALLOCA(mte_mke_dec_buff_bytes(decoder, encoded_bytes));
  mte_dec_args decoding_args = MTE_DEC_ARGS_INIT(NULL, 0, NULL, &decoder_timestamp_callback, NULL);
  MTE_SET_DEC_IO(decoding_args, encoded, encoded_bytes, mte_buffer);
  decoder_status = mte_mke_dec_decode(decoder, &decoding_args);
#endif

  // Ensure that there were no decoding errors.
  if (mte_base_status_is_error(decoder_status))
  {
    fprintf(stderr, "Error decoding: Status: %s/%s\n",
      mte_base_status_name(decoder_status),
      mte_base_status_description(decoder_status));
    fprintf(stderr, "Socket server closed due to decoding error.\n");
    return false;
  }

  // Set decoded message.
  *decoded_message = malloc(decoding_args.bytes + 1);
  memset(*decoded_message, '\0', decoding_args.bytes + 1);
  if (*decoded_message != 0 && decoding_args.decoded != 0)
  {
    memcpy(*decoded_message, decoding_args.decoded, decoding_args.bytes);
  }

  // Display decoded message.
  printf("Decoded message: %s\n", *decoded_message);

  /*-----------------------------------------------------------
   * Note that the caller must run a "free(*decoded_message)" after
   * processing the result. Otherwise a memory leak will occur!
   *---------------------------------------------------------*/
  return true;
}

void finish_mte()
{
  // Uninstantiate Encoder and Decoder.
#if defined USE_MTE_CORE
  mte_enc_uninstantiate(encoder);
  mte_dec_uninstantiate(decoder);
#endif
#if defined USE_MKE_ADDON
  mte_mke_enc_uninstantiate(encoder);
  mte_mke_dec_uninstantiate(decoder);
#endif
#if defined USE_FLEN_ADDON
  mte_flen_enc_uninstantiate(encoder);
  mte_dec_uninstantiate(decoder);
#endif

  // Free the Encoder and Decoder.
  free(encoder);
  free(decoder);
}

static bool exchange_mte_info()
{
  // The client Encoder and the server Decoder will be paired.
  // The client Decoder and the server Encoder will be paired.

  // Init buffers for incoming data.
  client_encoder_info.private_key.data = client_encoder_info.my_private_key;
  client_encoder_info.private_key.size = sizeof(client_encoder_info.my_private_key);
  client_encoder_info.public_key.data = client_encoder_info.my_public_key;
  client_encoder_info.public_key.size = sizeof(client_encoder_info.my_public_key);

  client_decoder_info.private_key.data = client_decoder_info.my_private_key;
  client_decoder_info.private_key.size = sizeof(client_decoder_info.my_private_key);
  client_decoder_info.public_key.data = client_decoder_info.my_public_key;
  client_decoder_info.public_key.size = sizeof(client_decoder_info.my_public_key);

  // Prepare to send client information.
  // Create the private and public keypairs for the client Encoder and Decoder.
  if (ecdh_p256_create_keypair(&client_encoder_info.private_key, &client_encoder_info.public_key, NULL, NULL) != ECDH_P256_SUCCESS) {
    fprintf(stderr, "Error occurred attempting to create keypairs.\n");
    return false;
  }

  if (ecdh_p256_create_keypair(&client_decoder_info.private_key, &client_decoder_info.public_key, NULL, NULL) != ECDH_P256_SUCCESS) {
    fprintf(stderr, "Error occurred attempting to create keypairs.\n");
    return false;
  }

  // Create personalization strings.
  create_guid(&client_encoder_info.personalization.data, &client_encoder_info.personalization.size);
  create_guid(&client_decoder_info.personalization.data, &client_decoder_info.personalization.size);

  // Send out information to the server.
  // 1 - client Encoder public key (to server Decoder)
  // 2 - client Encoder personalization string (to server Decoder)
  // 3 - client Decoder public key (to server Encoder)
  // 4 - client Decoder personalization string (to server Encoder)
  send_message('1', client_encoder_info.public_key.data, client_encoder_info.public_key.size);
  send_message('2', client_encoder_info.personalization.data, client_encoder_info.personalization.size);
  send_message('3', client_decoder_info.public_key.data, client_decoder_info.public_key.size);
  send_message('4', client_decoder_info.personalization.data, client_decoder_info.personalization.size);

  // Wait for ack from server.
  struct recv_msg recv_data = receive_message();
  if (recv_data.header != 'A')
  {
    return false;
  }

  // Free the malloc'd message.
  if (recv_data.message.data != NULL)
  {
    free(recv_data.message.data);
  }

  // Processing incoming messages, all 4 will be needed.
  uint8_t recv_count = 0;

  // Loop until all 4 data are received from server, can be in any order.
  while (recv_count < 4)
  {
    // Receive the next message from the server.
    recv_data = receive_message();

    // Evaluate the header.
    // 1 - client Decoder public key (from server Encoder)
    // 2 - client Decoder nonce (from server Encoder)
    // 3 - client Encoder public key (from server Decoder)
    // 4 - client Encoder nonce (from server Decoder)
    switch (recv_data.header)
    {
    case '1':
      if (client_decoder_info.peer_public_key.data != NULL)
      {
        free(client_decoder_info.peer_public_key.data);
      }
      else
      {
        recv_count++;
      }
      client_decoder_info.peer_public_key = create_byte_array_size(recv_data.message.size);
      client_decoder_info.peer_public_key.data = recv_data.message.data;
      break;
    case '2':
      if (client_decoder_info.nonce.data != NULL)
      {
        free(client_decoder_info.nonce.data);
      }
      else
      {
        recv_count++;
      }
      client_decoder_info.nonce = create_byte_array_pointer(recv_data.message.data, recv_data.message.size);
      break;
    case '3':
      if (client_encoder_info.peer_public_key.data != NULL)
      {
        free(client_encoder_info.peer_public_key.data);
      }
      else
      {
        recv_count++;
      }
      client_encoder_info.peer_public_key = create_byte_array_size(recv_data.message.size);
      client_encoder_info.peer_public_key.data = recv_data.message.data;
      break;
    case '4':
      if (client_encoder_info.nonce.data != NULL)
      {
        free(client_encoder_info.nonce.data);
      }
      else
      {
        recv_count++;
      }
      client_encoder_info.nonce = create_byte_array_pointer(recv_data.message.data, recv_data.message.size);
      break;
    default:
      // Unknown message, abort here, send an ‘E’ for error.
      send_message('E', "ERR", 3);
      return false;
    }
  }

  // Now all values from server have been received, send an 'A' for acknowledge to server.
  send_message('A', "ACK", 3);

  return true;
}

static mte_status encoder_entropy_input_callback(const void* context, mte_drbg_ei_info* info)
{
  (void)context;

  // Create byte array to hold secret data.
  byte_array secret = create_byte_array_size(SZ_ECDH_P256_SECRET_DATA);

  // Create shared secret. This is done here right before copying into the entropy so that the lifetime
  // of the secret will be as minimal as possible.
  int res = ecdh_p256_create_secret(client_encoder_info.private_key, client_encoder_info.peer_public_key, &secret);
  if (res < 0)
  {
    fprintf(stderr, "Error occurred attempting to create shared secret.\n");
    return false;
  }

  // Copy the shared secret to the entropy input buffer.
  memcpy(info->buff, secret.data, secret.size);

  // Set the entropy length.
  info->bytes = secret.size;
  return mte_status_success;
}

static mte_status decoder_entropy_input_callback(const void* context, mte_drbg_ei_info* info)
{
  (void)context;

  // Create byte array to hold secret data.
  byte_array secret = create_byte_array_size(SZ_ECDH_P256_SECRET_DATA);

  // Create shared secret. This is done here right before copying into the entropy so that the lifetime
  // of the secret will be as minimal as possible.
  int res = ecdh_p256_create_secret(client_decoder_info.private_key, client_decoder_info.peer_public_key, &secret);
  if (res < 0)
  {
    fprintf(stderr, "Error occurred attempting to create shared secret.\n");
    return false;
  }

  // Copy the shared secret to the entropy input buffer.
  memcpy(info->buff, secret.data, secret.size);

  // Set the entropy length.
  info->bytes = secret.size;
  return mte_status_success;
}

static void encoder_nonce_callback(const void* context, mte_drbg_nonce_info* info)
{
  (void)context;

  // Copy the nonce in little-endian format to the nonce buffer.
  info->buff = client_encoder_info.nonce.data;

  // Set the actual nonce length.
  info->bytes = client_encoder_info.nonce.size;
}

static void decoder_nonce_callback(const void* context, mte_drbg_nonce_info* info)
{
  (void)context;

  // Copy the nonce in little-endian format to the nonce buffer.
  info->buff = client_decoder_info.nonce.data;

  // Set the actual nonce length.
  info->bytes = client_decoder_info.nonce.size;
}

static uint64_t encoder_timestamp_callback(const void* context)
{
  (void)context;
  return get_timestamp();
}

static uint64_t decoder_timestamp_callback(const void* context)
{
  (void)context;
  return get_timestamp();
}

static uint64_t get_timestamp()
{
  return (uint64_t)time(NULL);
}

static void create_guid(char** guid, size_t* guid_bytes)
{
  // Allocate bytes for guid, and include one for the null terminator.
  *guid_bytes = 37;

  *guid = malloc(*guid_bytes);

  size_t temp_bytes = *guid_bytes / 2;

  // Create temp byte array at half the size needed size (so hex value can become guid). 
  byte_array temp;
  temp.data = MTE_ALLOCA(temp_bytes);
  temp.size = temp_bytes;

  // Randomly generate values for temp array.
  ecdh_p256_random(temp);

  // Convert temp to hex, then copy these to guid byte array.
  memcpy(*guid, bytes_to_hex(temp.data, temp_bytes), *guid_bytes);
  if (*guid != NULL)
  {
    // Create array to hold hyphen '-' positions.
    const uint8_t hyphens[] = { 8, 13, 18, 23 };

    // Set hyphen '-' symbol at designated positions.
    for (uint8_t i = 0; i < sizeof(hyphens); i++)
    {
      (*guid)[hyphens[i]] = '-';
    }

    // Subtract one for the null terminator, the other side will need the actual length.
    *guid_bytes = *guid_bytes - 1;
  }
}

static char* bytes_to_hex(const uint8_t* in, size_t insz) {
  if (LOGBUF_SZ < (2 * insz + 1)) {
    insz = (LOGBUF_SZ - 1) / 2;
  }
  const uint8_t* pin = in;
  const char* hex = "0123456789ABCDEF";
  char* pout = logbuf;
  while (pin < in + insz) {
    *pout++ = hex[(*pin >> 4) & 0xF];
    *pout++ = hex[*pin++ & 0xF];
  }
  *pout = 0;
  return logbuf;
}

static void display_message_base64(const uint8_t* message, size_t message_bytes)
{
  size_t base64_encoded_bytes = mte_base64_encode_bytes(message_bytes);
  char* base64_buffer;
  base64_buffer = malloc(base64_encoded_bytes);
  mte_base64_encode(message, message_bytes, base64_buffer);
  printf("Base64 Encoded representation: %s\n", base64_buffer);
  free(base64_buffer);
}

static void display_message_hex(const uint8_t* message, size_t message_bytes)
{
  printf("Hex representation: %s\n", bytes_to_hex(message, message_bytes));
}

static void display_message_all(const uint8_t* message, size_t message_bytes)
{
#if defined DISPLAY_B64
  display_message_base64(message, message_bytes);
#endif
#if defined DISPLAY_HEX
  display_message_hex(message, message_bytes);
#endif
}

static byte_array create_byte_array_size(size_t size)
{
  // Create temp byte array with size based on parameter.
  byte_array temp;
  temp.size = size;

  if (size == 0)
  {
    // Set data to null.
    temp.data = NULL;
  }
  else
  {
    // Create new uint8_t byte array based on size.
    temp.data = malloc(size);
  }
  return temp;
}

static byte_array create_byte_array(const byte_array source)
{
  // If size is zero or data is null, return empty byte array.
  if (source.size == 0 || source.data == NULL)
  {
    return create_byte_array_size(0);
  }

  // Copy the data from the source into the destination temp.
  byte_array temp;
  temp.size = source.size;
  temp.data = malloc(source.size);
  if (temp.data != 0)
  {
    memcpy(temp.data, source.data, temp.size);
  }

  return temp;
}

static byte_array create_byte_array_pointer(uint8_t* source, size_t size)
{
  // If size is zero or data is null, return empty byte array.
  if (size == 0 || source == NULL)
  {
    return create_byte_array_size(0);
  }

  // Copy the data from the source into the destination temp.
  byte_array temp;
  temp.size = size;
  temp.data = source;

  return temp;
}

