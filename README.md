

<img src="Eclypses.png" style="width:50%;margin-right:0;"/>

<div align="center" style="font-size:40pt; font-weight:900; font-family:arial; margin-top:300px; " >
C Socket Tutorial</div>
<br>
<div align="center" style="font-size:28pt; font-family:arial; " >
MTE Implementation Tutorial (MTE Core, MKE, MTE Fixed Length)</div>
<br>
<div align="center" style="font-size:15pt; font-family:arial; " >
Using MTE version 3.1.x</div>





[Introduction](#introduction)

[Socket Tutorial Server and Client](#socket-tutorial-server-and-client)


<div style="page-break-after: always; break-after: page;"></div>

# Introduction

This tutorial is sending messages via a socket connection. This is only a sample, the MTE does NOT require the usage of sockets, you can use whatever communication protocol that is needed.

This tutorial demonstrates how to use Mte Core, Mte MKE and Mte Fixed Length. For this application, only one type can be used at a time; however, it is possible to implement any and all at the same time depending on needs.

This tutorial contains two main programs, a client and a server, and also for Windows and Linux. Note that any of the available languages can be used for any available platform as long as communication is possible. It is just recommended that a server program is started first and then a client program can be started.

The MTE Encoder and Decoder need several pieces of information to be the same in order to function properly. This includes entropy, nonce, and personalization. If this information must be shared, the entropy MUST be passed securely. One way to do this is with a Diffie-Hellman approach. Each side will then be able to create two shared secrets to use as entropy for each pair of Encoder/Decoder. The two personalization values will be created by the client and shared to the other side. The two nonce values will be created by the server and shared.

The SDK that you received from Eclypses may not include the MKE or MTE FLEN add-ons. If your SDK contains either the MKE or the Fixed Length add-ons, the name of the SDK will contain "-MKE" or "-FLEN". If these add-ons are not there and you need them please work with your sales associate. If there is no need, please just ignore the MKE and FLEN options.

Here is a short explanation of when to use each, but it is encouraged to either speak to a sales associate or read the dev guide if you have additional concerns or questions.

***MTE Core:*** This is the recommended version of the MTE to use. Unless payloads are large or sequencing is needed this is the recommended version of the MTE and the most secure.

***MTE MKE:*** This version of the MTE is recommended when payloads are very large, the MTE Core would, depending on the token byte size, be multiple times larger than the original payload. Because this uses the MTE technology on encryption keys and encrypts the payload, the payload is only enlarged minimally.

***MTE Fixed Length:*** This version of the MTE is very secure and is used when the resulting payload is desired to be the same size for every transmission. The Fixed Length add-on is mainly used when using the sequencing verifier with MTE. In order to skip dropped packets or handle asynchronous packets the sequencing verifier requires that all packets be a predictable size. If you do not wish to handle this with your application then the Fixed Length add-on is a great choice. This is ONLY an encoder change - the decoder that is used is the MTE Core decoder.

***IMPORTANT NOTE***
>If using the fixed length MTE (FLEN), all messages that are sent that are longer than the set fixed length will be trimmed by the MTE. The other side of the MTE will NOT contain the trimmed portion. Also messages that are shorter than the fixed length will be padded by the MTE so each message that is sent will ALWAYS be the same length. When shorter message are "decoded" on the other side the MTE takes off the extra padding when using strings and hands back the original shorter message, BUT if you use the raw interface the padding will be present as all zeros. Please see official MTE Documentation for more information.

In this tutorial, there is an MTE Encoder on the client that is paired with an MTE Decoder on the server. Likewise, there is an MTE Encoder on the server that is paired with an MTE Decoder on the client. Secured messages wil be sent to and from both sides. If a system only needs to secure messages one way, only one pair could be used.

**IMPORTANT**
>Please note the solution provided in this tutorial does NOT include the MTE library or supporting MTE library files. If you have NOT been provided an MTE library and supporting files, please contact Eclypses Inc. The solution will only work AFTER the MTE library and MTE library files have been incorporated.
  

# Socket Tutorial Server and Client

## MTE Directory and File Setup
<ol>
<li>
Navigate to the "tutorial-mte-socket-c" directory.
</li>
<li>
Create a directory named "MTE". This will contain all needed MTE files.
</li>
<li>
Copy the "lib" directory and contents from the MTE SDK into the "MTE" directory.
</li>
<li>
Copy the "include" directory and contents from the MTE SDK into the "MTE" directory.
</li>
</ol>

## ECDH Directory and File Setup
<ol>
<li>
Navigate to the "tutorial-mte-socket-c" directory.
</li>
<li>
Create a directory named "ecdh". This will contain all needed ecdh files.
</li>
<li>
Copy the "lib" directory and contents from the ecdh SDK into the "ecdh" directory.
</li>
<li>
Copy the "include" directory and contents from the ecdh SDK into the "ecdh" directory.
</li>
</ol>

The common source code between the client and server will be found in the "common" directory. The client and server specific source code will be found in their respective directories.

## Project Settings
<ol>
<li>
Ensure that the include directory path contains the path to the "MTE/include", "ecdh/include", and "common" directories. 
</li>
<li>
Ensure that the library directory path contains the path to the "MTE/lib" and "ecdh/lib" directories.
</li>
<li>
The project will require either the dynamic MTE library or the static libraries depending on add-ons; for MTE Core: mte_mtee, mte_mted, and mte_mteb in that order; for MKE add-on: mte_mkee, mte_mked, mte_mtee, mte_mted, and mte_mteb in that order; or for Fixed length add-on: mte_flen, mte_mtee, mte_mted, and mte_mteb in that order.
</li>
</ol>

## Source Code Key Points

### MTE Setup

<ol>
<li>
Utilize preprocessor directives to more easily handle the function calls for the MTE Core or the add-on configurations. In the file "globals.h", uncomment 'USE_MTE_CORE' to utilize the main MTE Core functions; uncomment 'USE_MKE_ADDON' to use the MTE MKE add-on functions; or uncomment 'USE_FLEN_ADDON' to use the Fixed length add-on functions. In this application, only one can be used at a time. This file is shared between the two projects, so both projects will have the changes reflected accordingly.

```c
//-----------------------------------
// To use the core MTE, uncomment the
// following preprocessor definition.
//-----------------------------------
#define USE_MTE_CORE
//---------------------------------------
// To use the MTE MKE add-on, uncomment
// the following preprocessor definition.
//---------------------------------------
//#define USE_MKE_ADDON
//-------------------------------------------------
// To use the MTE Fixed length add-on,
// uncomment the following preprocessor definition.
//-------------------------------------------------
//#define USE_FLEN_ADDON
```

</li>

<li>
In this application, the Eclypses Elliptic Curve Diffie-Hellman (ECDH) support package is used to create entropy public and private keys. The public keys are then shared between the client and server, and then shared secrets are created to use as matching entropy for the creation of the Encoders and Decoders. The personalization strings and nonces are also created using the randomization feature of the support package.

```c
// Create the private and public keypairs for the client Encoder and Decoder.
if (ecdh_p256_create_keypair(client_encoder_info.private_key, client_encoder_info.public_key, NULL, NULL) != ECDH_P256_SUCCESS) {
  fprintf(stderr, "Error occurred attempting to create keypairs.\n");
  return false;
}

if (ecdh_p256_create_keypair( client_decoder_info.private_key, client_decoder_info.public_key, NULL, NULL) != ECDH_P256_SUCCESS) {
  fprintf(stderr, "Error occurred attempting to create keypairs.\n");
  return false;
}
  ```
</li>
<li>
The public keys created by the client will be sent to the server, and vice versa, and will be received as <i>peer public keys</i>. Then the shared secret can be created on each side. These should match as long as the information has been created and shared correctly.

```c
// Create byte array to hold secret data.
byte_array secret = create_byte_array_size(SZ_ECDH_P256_SECRET_DATA);

// Create shared secret.
int res = ecdh_p256_create_secret( client_encoder_info.private_key, client_encoder_info.peer_public_key, secret);
if (res < 0)
{
  fprintf(stderr, "Error occurred attempting to create shared secret.\n");
  return false;
}
```
These secrets will then be used to fufill the entropy needed for the Encoders and Decoders.
</li>
<li>
The client will create the personalization strings, in this case a guid-like structure using the ECDH randomizer.

```c
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

  // Create array to hold hyphen '-' positions.
  const uint8_t hyphens[] = {8, 13, 18, 23};

  // Set hyphen '-' symbol at designated positions.
  for (uint8_t i = 0; i < sizeof(hyphens); i++)
  {
    (*guid)[hyphens[i]] = '-';
  }

  // Subtract one for the null terminator, the other side will need the actual length.
  *guid_bytes = *guid_bytes - 1;
}
```
</li>
<li>
The two public keys and the two personalization strings will then be sent to the server. The client will wait for an awknowledgment.

```c
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
```
</li>
<li>
The server will wait for the two public keys and the two personalization strings from the client. Once all four pieces of information have been received, it will send an awknowledgment.

```c
// Processing incoming messages, all 4 will be needed.
uint8_t recv_count = 0;
struct recv_msg recv_data;

// Loop until all 4 data are received from client, can be in any order.
while (recv_count < 4)
{
  // Receive the next message from the client.
  recv_data = receive_message();

  // Evaluate the header.
  // 1 - server Decoder public key (from client Encoder)
  // 2 - server Decoder personalization string (from client Encoder)
  // 3 - server Encoder public key (from client Decoder)
  // 4 - server Encoder personalization string (from client Decoder)

  switch (recv_data.header)
  {
  case '1':
    if (server_decoder_info.peer_public_key.data != NULL)
    {
      free(server_decoder_info.peer_public_key.data);
    }
    else
    {
      recv_count++;
    }
    server_decoder_info.peer_public_key = create_byte_array_size(recv_data.message.size);
    server_decoder_info.peer_public_key.data = recv_data.message.data;
    break;
  case '2':
    if (server_decoder_info.personalization.size != 0)
    {
      free(server_decoder_info.personalization.data);
    }
    else
    {
      recv_count++;
    }
    server_decoder_info.personalization = create_byte_array_pointer(recv_data.message.data, recv_data.message.size);
    break;
  case '3':
    if (server_encoder_info.peer_public_key.data != NULL)
    {
      free(server_encoder_info.peer_public_key.data);
    }
    else
    {
      recv_count++;
    }
    server_encoder_info.peer_public_key = create_byte_array_size(recv_data.message.size);
    server_encoder_info.peer_public_key.data = recv_data.message.data;
    break;
  case '4':
    if (server_encoder_info.personalization.size != 0)
    {
      free(server_encoder_info.personalization.data);
    }
    else
    {
      recv_count++;
    }
    server_encoder_info.personalization = create_byte_array_pointer(recv_data.message.data, recv_data.message.size);
    break;
  default:
    // Unknown message, abort here, send an ‘E’ for error.
    send_message('E', "ERR", 3);
    return false;
  }
}

// Now all values from client have been received, send an 'A' for acknowledge to client.
send_message('A', "ACK", 3);
```
</li>
<li>
The server will create the private and public keypairs, one for the server Encoder and client Decoder, and one for the server Decoder and client Encoder.

```c
// Create the private and public keypairs for the server Encoder and Decoder.
if (ecdh_p256_create_keypair(server_encoder_info.private_key, server_encoder_info.public_key, NULL, NULL) != ECDH_P256_SUCCESS) {
  fprintf(stderr, "Error occurred attempting to create keypairs.\n");
  return false;
}

if (ecdh_p256_create_keypair(server_decoder_info.private_key, server_decoder_info.public_key, NULL, NULL) != ECDH_P256_SUCCESS) {
  fprintf(stderr, "Error occurred attempting to create keypairs.\n");
  return false;
}
```

</li>
<li>
The server will create the nonces, using the platform supplied secure RNG.

```c
// Create nonces.
size_t min_nonce_bytes = mte_base_drbgs_nonce_min_bytes(MTE_DRBG_ENUM);
if (min_nonce_bytes == 0)
{
  min_nonce_bytes = 1;
}

byte_array server_encoder_nonce;

server_encoder_info.nonce = create_byte_array_size(min_nonce_bytes);
ecdh_p256_random(server_encoder_info.nonce);

server_decoder_info.nonce = create_byte_array_size(min_nonce_bytes);
ecdh_p256_random(server_decoder_info.nonce);
```
</li>
<li>
The two public keys and the two nonces will then be sent to the client. The server will wait for an awknowledgment. 
```c
// Send out information to the client.
// 1 - server Encoder public key (to client Decoder)
// 2 - server Encoder nonce (to client Decoder)
// 3 - server Decoder public key (to client Encoder)
// 4 - server Decoder nonce (to client Encoder)
send_message('1', server_encoder_info.public_key.data, server_encoder_info.public_key.size);
send_message('2', server_encoder_info.nonce.data, server_encoder_info.nonce.size);
send_message('3', server_decoder_info.public_key.data, server_decoder_info.public_key.size);
send_message('4', server_decoder_info.nonce.data, server_decoder_info.nonce.size);

// Wait for ack from client.
recv_data = receive_message();

// Free the malloc'd message.
if (recv_data.message.data != NULL)
{
  free(recv_data.message.data);
}
```
</li>

<li>
The client will now wait for information from the server. This includes the two server public keys, and the two nonces. Once all pieces of information have been obtained, the client will send an awknowledgment back to the server.

```c
// Processing incoming messages, all 4 will be needed.
uint8_t recv_count = 0;

// Loop until all 4 data are received from server, can be in any order.
while (recv_count < 4)
{
  // Receive the next message from the server.
  recv_data = receive_message();

  char* ptr;

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
```

</li>
<li>
After the client and server have exchanged their information, the client and server can each create their respective Encoder and Decoder. This is where the personalization string will be added. Additionally, the entropy and nonce callback functions will be called. This sample code showcases the client Encoder. There will be four of each of these that will be very similar. Ensure carefully that each function uses the appropriate client/server, and Encoder/Decoder variables and functions.

```c
// Create the Encoder with the default options.
mte_enc_init_info encoder_info = MTE_ENC_INIT_INFO_INIT(
  MTE_DRBG_ENUM, MTE_TOKBYTES, MTE_VERIFIERS_ENUM, NULL, NULL);
encoder = malloc(mte_enc_state_bytes(&encoder_info));

// Initiate the Encoder state.
encoder_status = mte_enc_state_init(encoder, &encoder_info);

if (encoder_status != mte_status_success)
{
  printf("Encoder init error (%s): %s\n",
    mte_base_status_name(encoder_status),
    mte_base_status_description(encoder_status));
  return false;
}

// Set the Encoder instantiation information.
mte_drbg_inst_info enc_inst_info = { &encoder_entropy_input_callback, NULL, &encoder_nonce_callback, NULL, client_encoder_info.personalization, client_encoder_info.personalization_bytes };

// Instantiate the Encoder.
encoder_status = mte_enc_instantiate(encoder, &enc_inst_info);

if (encoder_status != mte_status_success)
{
  fprintf(stderr, "Encoder instantiate error (%s): %s\n",
    mte_base_status_name(encoder_status),
    mte_base_status_description(encoder_status));
  return false;
}

```

</li>
<li>
The entropy callback function will use the client Encoder private key and the public key sent from the server to generate a shared secret. This is then used as the entropy.

```c
static void encoder_nonce_callback(void* context, mte_drbg_nonce_info* info)
{
  (void)context;

  // Copy the nonce in little-endian format to the nonce buffer.
  info->buff = client_encoder_info.nonce;  

  // Set the actual nonce length.
  info->bytes = client_encoder_info.nonce_bytes;
}
```
</li>
<li>
The nonce callback function will set the Encoder nonce obtained from the server.

```c
static void encoder_nonce_callback(void* context, mte_drbg_nonce_info* info)
{
  MTE_SIZE8_T i;
  (void)context;

  // Copy the nonce in little-endian format to the nonce buffer.
  for (i = 0; i < info->max_length && i < sizeof(server_encoder_info.nonce); ++i)
  {
    info->buff[i] = (MTE_UINT8_T)(server_encoder_info.nonce >> (i * 8));
  }

  for (; i < info->min_length; ++i)
  {
    info->buff[i] = 0;
  }

  // Set the actual nonce length.
  info->bytes = i;
}
```
</li>
</ol>

### Diagnostic Test
<ol>
<li>
The application will run a diagnostic test, where the client will encode the word "ping", then send the encoded message to the server. The server will decode the received message to confirm that the original message is "ping". Then the server will encode the word "ack" and send the encoded message to the client. The client then decodes the received message, and confirms that it decodes it to the word "ack". 
</li>
</ol>

### User Interaction
<ol>
<li>
The application will continously prompt the user for an input (until the user types "quit"). That input will be encoded with the client Encoder and sent to the server.

```c
Bool encode_message(const char* message, char** encoded, size_t* encoded_bytes)
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
```
</li>
<li>
The server will use its Decoder to decode the message.

```c
Bool decode_message(char* encoded, size_t encoded_bytes, char** decoded_message)
{
  // Display encoded message.
#if defined DISPLAY_HEX || defined DISPLAY_B64
  printf("\nEncoded message received:\n");
  display_message_all(encoded, encoded_bytes);
#endif

  // Decode the encoded message.
#if defined USE_MTE_CORE || defined USE_FLEN_ADDON
  uint8_t* mte_buffer = alloca(mte_dec_buff_bytes(decoder, encoded_bytes));
  mte_dec_args decoding_args = MTE_DEC_ARGS_INIT(NULL, 0, NULL, &get_timestamp, NULL);
  MTE_SET_DEC_IO(decoding_args, encoded, encoded_bytes, mte_buffer);
  decoder_status = mte_dec_decode(decoder, &decoding_args);
#endif
#if defined USE_MKE_ADDON
  uint8_t* mte_buffer = alloca(mte_mke_dec_buff_bytes(decoder, encoded_bytes));
  mte_dec_args decoding_args = MTE_DEC_ARGS_INIT(NULL, 0, NULL, &get_timestamp, NULL);
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
  memcpy(*decoded_message, decoding_args.decoded, decoding_args.bytes);

  // Display decoded message.
  printf("Decoded message: %s\n", *decoded_message);

  /*-----------------------------------------------------------
   * Note that the caller must run a "free(*decoded_message)" after
   * processing the result. Otherwise a memory leak will occur!
   *---------------------------------------------------------*/
  return true;
}
```

</li>
<li>
Then that message will be re-encoded with the server Encoder and sent to the client.The client Decoder will then decode that message, which then will be compared with the original user input.
</li>
</ol>

### MTE Finialize

<ol>
<li>
Once the user has stopped the user input, the program should securely clear out MTE Encoder and Decoder information.

```c

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
```
</li>
</ol>

<div style="page-break-after: always; break-after: page;"></div>

# Contact Eclypses

<img src="Eclypses.png" style="width:8in;"/>

<p align="center" style="font-weight: bold; font-size: 22pt;">For more information, please contact:</p>
<p align="center" style="font-weight: bold; font-size: 22pt;"><a href="mailto:info@eclypses.com">info@eclypses.com</a></p>
<p align="center" style="font-weight: bold; font-size: 22pt;"><a href="https://www.eclypses.com">www.eclypses.com</a></p>
<p align="center" style="font-weight: bold; font-size: 22pt;">+1.719.323.6680</p>

<p style="font-size: 8pt; margin-bottom: 0; margin: 300px 24px 30px 24px; " >
<b>All trademarks of Eclypses Inc.</b> may not be used without Eclypses Inc.'s prior written consent. No license for any use thereof has been granted without express written consent. Any unauthorized use thereof may violate copyright laws, trademark laws, privacy and publicity laws and communications regulations and statutes. The names, images and likeness of the Eclypses logo, along with all representations thereof, are valuable intellectual property assets of Eclypses, Inc. Accordingly, no party or parties, without the prior written consent of Eclypses, Inc., (which may be withheld in Eclypses' sole discretion), use or permit the use of any of the Eclypses trademarked names or logos of Eclypses, Inc. for any purpose other than as part of the address for the Premises, or use or permit the use of, for any purpose whatsoever, any image or rendering of, or any design based on, the exterior appearance or profile of the Eclypses trademarks and or logo(s).
</p>