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
#undef UNICODE
#define BIG_ENDIAN 0
#define LITTLE_ENDIAN 1

//---------------------------------------------------
// MKE and Fixed length add-ons are NOT in all SDK
// MTE versions. If the name of the SDK includes
// "-MKE" then it will contain the MKE add-on. If the
// name of the SDK includes "-FLEN" then it contains
// the Fixed length add-on.
//---------------------------------------------------

/* Step 5 */
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

#if defined _WIN32
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#define strcasecmp  _stricmp
#pragma comment (lib, "Ws2_32.lib")
#else
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#endif
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Step 6 */
#if !defined mte_alloca_h
#include "mte_alloca.h"
#endif
#if !defined mte_license_h
#include "mte_license.h"
#endif
#if !defined mte_init_h
#include "mte_init.h"
#endif
#if !defined mte_base64_h
#include "mte_base64.h"
#endif
#if defined USE_MTE_CORE
#if !defined mte_enc_h
#include "mte_enc.h"
#endif
#if !defined mte_dec_h
#include "mte_dec.h"
#endif
const char* mte_type = "Core";
#endif

#if defined USE_MKE_ADDON
#if !defined mte_mke_enc_h
#include "mte_mke_enc.h"
#endif
#if !defined mte_mke_dec_h
#include "mte_mke_dec.h"
#endif
const char* mte_type = "MKE";
#endif

#if defined USE_FLEN_ADDON
#if !defined mte_flen_enc_h
#include "mte_flen_enc.h"
#endif
#if !defined mte_dec_h
#include "mte_dec.h"
#endif
const char* mte_type = "FLEN";
#endif

#define DEFAULT_BUFLEN 2048
#define DEFAULT_PORT "27015"
#define DEFAULT_SERVER_IP "localhost"

/* Step 8 */
MTE_HANDLE g_decoder;
mte_status g_decoder_status;
MTE_HANDLE g_encoder;
mte_status g_encoder_status;

/* Step 9 - Continue */
// Set default entropy, nonce and identifier
// Providing Entropy in this fashion is insecure. This is for demonstration purposes only and should never be done in practice. 
// This is a trial version of the MTE, so entropy must be blank
// OPTIONAL!!! adding 1 to Decoder nonce so return value changes -- same nonce can be used for Encoder and Decoder
// on client side values will be switched so they match up Encoder to Decoder and vice versa

int g_encoder_nonce = 1;
int g_decoder_nonce = 0;
char* g_personal = "demo";

// Set Timestamp and sequence window for Decoder
static const uint64_t g_timestamp_window = 1;
static const int32_t g_sequence_window = 0;

/// <summary>
/// Determines the byte order (big endian or little endian).
/// </summary>
/// <returns></returns>
static int test_byte_order();

/// <summary>
/// The callback function for the Encoder's entropy input.
/// </summary>
static mte_status encoder_entropy_input_callback(void* context, mte_drbg_ei_info* info);

/// <summary>
/// The callback function for the Decoder's entropy input.
/// </summary>
static mte_status decoder_entropy_input_callback(void* context, mte_drbg_ei_info* info);

/// <summary>
/// The callback function for the Encoder's nonce.
/// </summary>
static void encoder_nonce_callback(void* context, mte_drbg_nonce_info* info);

/// <summary>
/// The callback function for the Decoder's nonce.
/// </summary>
static void decoder_nonce_callback(void* context, mte_drbg_nonce_info* info);

/// <summary>
/// The callback function for the Encoder's timestamp.
/// </summary>
static uint64_t encoder_timestamp_callback(void* context);

/// <summary>
/// The callback function for the Decoder's timestamp.
/// </summary>
static uint64_t decoder_timestamp_callback(void* context);

/// <summary>
/// Creates the socket.
/// </summary>
/// <returns></returns>
static int create_socket();

/// <summary>
/// Closes the socket.
/// </summary>
static void close_socket();

/// <summary>
/// Determines if the socket is valid.
/// </summary>
/// <returns></returns>
static int is_socket_valid();

/// <summary>
/// Sends the data through the socket.
/// </summary>
/// <param name="data">The data to be sent.</param>
/// <param name="data_size">The size of the data.</param>
/// <returns>The number of bytes sent.</returns>
static size_t send_data(const char* data, uint32_t data_size);

/// <summary>
/// Receives the data through the socket.
/// </summary>
/// <param name="data">The data to be received.</param>
/// <param name="data_size">The size of the data.</param>
/// <returns></returns>
static size_t recv_data(char* data, uint32_t data_size);

/// <summary>
/// Connects to the socket.
/// </summary>
/// <param name="host"></param>
/// <param name="port"></param>
/// <returns></returns>
static int connect_socket(const char* host, uint16_t port);

int32_t m_sock = -1;
struct sockaddr_in m_addr;
struct sockaddr_in rm_addr;
struct hostent* hp;

union bytes_length
{
  uint32_t length;
  char byte_array[4];
};

int main(void)
{
  //
  // This tutorial uses Sockets for communication.
  // It should be noted that the MTE can be used with any type of communication. (SOCKETS are not required!)
  //

  printf("Starting C Socket Client.\n");

  /* Step 7 */
 // Initialize MTE.
  if (!mte_init(NULL, NULL))
  {
    fprintf(stderr, "MTE init error.");
    return -1;
  }

  // Display what version of MTE we are using
  const char* mte_version = mte_base_version();
  printf("Using MTE Version: %s-%s\n", mte_version, mte_type);

  printf("Please enter ip address of Server, press Enter to use default: %s\n", DEFAULT_SERVER_IP);
  char ipaddress[100];
  fflush(stdout);
  (void)!fgets(ipaddress, sizeof(ipaddress), stdin);
  ipaddress[strcspn(ipaddress, "\r\n")] = 0;
  if (strlen(ipaddress) == 0)
  {
    memcpy(ipaddress, DEFAULT_SERVER_IP, sizeof(DEFAULT_SERVER_IP));
  }

  printf("Server is at %s\n", ipaddress);

  printf("Please enter port to use, press Enter to use default: %s\n", DEFAULT_PORT);
  char port[10];
  fflush(stdout);
  (void)!fgets(port, sizeof(port), stdin);
  port[strcspn(port, "\r\n")] = 0;
  if (strlen(port) == 0)
  {
    memcpy(port, DEFAULT_PORT, sizeof(DEFAULT_PORT));
  }

  /* Step 10 */
  // Check MTE license.
  // Initialize MTE license. If a license code is not required (e.g., trial
  // mode), this can be skipped. This demo attempts to load the license info
  // from the environment if required.
  if (!mte_license_init("LicenseCompanyName", "LicenseKey"))
  {
    printf("There was an error attempting to initialize the MTE License.\n");
    return 1;
  }

  /* Step 11 */
#if defined USE_MTE_CORE
  //
  // Create the Encoder
  mte_enc_init_info e_info = MTE_ENC_INIT_INFO_INIT(
    MTE_DRBG_ENUM, MTE_TOKBYTES, MTE_VERIFIERS_ENUM, NULL, NULL);
  g_encoder = MTE_ALLOCA(mte_enc_state_bytes(&e_info));

  //
  // Create the Decoder
  mte_dec_init_info d_info = MTE_DEC_INIT_INFO_INIT(
    MTE_DRBG_ENUM, MTE_TOKBYTES, MTE_VERIFIERS_ENUM, g_timestamp_window, g_sequence_window, NULL, NULL);
  g_decoder = MTE_ALLOCA(mte_dec_state_bytes(&d_info));
#endif
#if defined USE_MKE_ADDON
  //
  // Create the Encoder
  mte_mke_enc_init_info e_info = MTE_MKE_ENC_INIT_INFO_INIT(
    MTE_DRBG_ENUM, MTE_TOKBYTES, MTE_VERIFIERS_ENUM, MTE_CIPHER_ENUM,
    MTE_HASH_ENUM, NULL, NULL, NULL, NULL, NULL, NULL);
  g_encoder = MTE_ALLOCA(mte_mke_enc_state_bytes(&e_info));

  //
  // Create the Decoder
  mte_mke_dec_init_info d_info = MTE_MKE_DEC_INIT_INFO_INIT(
    MTE_DRBG_ENUM, MTE_TOKBYTES, MTE_VERIFIERS_ENUM, MTE_CIPHER_ENUM,
    MTE_HASH_ENUM, g_timestamp_window, g_sequence_window, NULL, NULL, NULL, NULL, NULL, NULL);
  g_decoder = MTE_ALLOCA(mte_mke_dec_state_bytes(&d_info));
#endif
#if defined USE_FLEN_ADDON
  //
  // Create the Encoder
  uint32_t fixed_bytes = 8;
  mte_flen_enc_init_info e_info = MTE_FLEN_ENC_INIT_INFO_INIT(
    MTE_DRBG_ENUM, MTE_TOKBYTES, MTE_VERIFIERS_ENUM, fixed_bytes, NULL, NULL);
  g_encoder = MTE_ALLOCA(mte_flen_enc_state_bytes(&e_info));

  //
  // Create the Decoder
  mte_dec_init_info d_info = MTE_DEC_INIT_INFO_INIT(
    MTE_DRBG_ENUM, MTE_TOKBYTES, MTE_VERIFIERS_ENUM, g_timestamp_window, g_sequence_window, NULL, NULL);
  g_decoder = MTE_ALLOCA(mte_dec_state_bytes(&d_info));
#endif

  uint32_t personal_bytes = (uint32_t)strlen(g_personal);

  mte_drbg_inst_info enc_inst_info =
  { &encoder_entropy_input_callback, NULL, &encoder_nonce_callback, NULL, g_personal, personal_bytes };
  mte_drbg_inst_info dec_inst_info =
  { &decoder_entropy_input_callback, NULL, &decoder_nonce_callback, NULL, g_personal, personal_bytes };


#if defined USE_MTE_CORE
  g_encoder_status = mte_enc_state_init(g_encoder, &e_info);
#endif
#if defined USE_MKE_ADDON
  g_encoder_status = mte_mke_enc_state_init(g_encoder, &e_info);
#endif
#if defined USE_FLEN_ADDON
  g_encoder_status = mte_flen_enc_state_init(g_encoder, &e_info);
#endif

  if (g_encoder_status != mte_status_success)
  {
    printf("Encoder state initialize error (%s): %s\n",
      mte_base_status_name(g_encoder_status),
      mte_base_status_description(g_encoder_status));
    return g_encoder_status;
  }

#if defined USE_MTE_CORE
  g_encoder_status = mte_enc_instantiate(g_encoder, &enc_inst_info);
#endif
#if defined USE_MKE_ADDON
  g_encoder_status = mte_mke_enc_instantiate(g_encoder, &enc_inst_info);
#endif
#if defined USE_FLEN_ADDON
  g_encoder_status = mte_flen_enc_instantiate(g_encoder, &enc_inst_info);
#endif

  if (g_encoder_status != mte_status_success)
  {
    printf("Encoder instantiate error (%s): %s\n",
      mte_base_status_name(g_encoder_status),
      mte_base_status_description(g_encoder_status));
    return g_encoder_status;
  }

#if defined USE_MTE_CORE || defined USE_FLEN_ADDON
  g_decoder_status = mte_dec_state_init(g_decoder, &d_info);
#endif
#if defined USE_MKE_ADDON
  g_decoder_status = mte_mke_dec_state_init(g_decoder, &d_info);
#endif

  if (g_decoder_status != mte_status_success)
  {
    printf("Decoder state initialize error (%s): %s\n",
      mte_base_status_name(g_decoder_status),
      mte_base_status_description(g_decoder_status));
    return g_decoder_status;
  }

#if defined USE_MTE_CORE || defined USE_FLEN_ADDON
  g_decoder_status = mte_dec_instantiate(g_decoder, &dec_inst_info);
#endif
#if defined USE_MKE_ADDON
  g_decoder_status = mte_mke_dec_instantiate(g_decoder, &dec_inst_info);
#endif

  if (g_decoder_status != mte_status_success)
  {
    printf("Decoder instantiate error (%s): %s\n",
      mte_base_status_name(g_decoder_status),
      mte_base_status_description(g_decoder_status));
    return g_decoder_status;
  }

  char text_to_send[100];

  memset(&m_addr, 0, sizeof(m_addr));
  memset(&rm_addr, 0, sizeof(rm_addr));

  char recv_buf[DEFAULT_BUFLEN];

  // Initialize socket
#if defined _WIN32
  Sleep(1000);
#else
  sleep(1);
#endif

  int socket_creation = create_socket();
  if (socket_creation == 0)
  {
    printf("Unable to create socket.");
    return socket_creation;
  }

  int socket_connection = connect_socket(ipaddress, (uint16_t)atoi(port));
  if (socket_connection == 0)
  {
    printf("Unable to connect to socket.");
    return socket_connection;
  }

  printf("Client connected to Server.\n");

  while (1)
  {
    //
    // Prompt user for input to send to other side
    printf("Please enter text to send: (To end please type 'quit')\n");
    fflush(stdout);
    fgets(text_to_send, 100, stdin);
    text_to_send[strcspn(text_to_send, "\r\n")] = 0;
    if (strcasecmp(text_to_send, "quit") == 0)
    {
      break;
    }

    /* Step 12 */
    // Encode text to send
    const uint32_t text_length = (uint32_t)strlen(text_to_send);

#if defined USE_MTE_CORE    
    char* encoded = MTE_ALLOCA(mte_enc_buff_bytes(g_encoder, text_length));
    mte_enc_args e_args = MTE_ENC_ARGS_INIT(NULL, 0, NULL, &encoder_timestamp_callback, NULL);
    MTE_SET_ENC_IO(e_args, text_to_send, text_length, encoded);
    g_encoder_status = mte_enc_encode(g_encoder, &e_args);
#endif
#if defined USE_MKE_ADDON
    char* encoded = MTE_ALLOCA(mte_mke_enc_buff_bytes(g_encoder, text_length));
    mte_enc_args e_args = MTE_ENC_ARGS_INIT(NULL, 0, NULL, &encoder_timestamp_callback, NULL);
    MTE_SET_ENC_IO(e_args, text_to_send, text_length, encoded);
    g_encoder_status = mte_mke_enc_encode(g_encoder, &e_args);
#endif
#if defined USE_FLEN_ADDON
    char* encoded = MTE_ALLOCA(mte_flen_enc_buff_bytes(g_encoder));
    mte_enc_args e_args = MTE_ENC_ARGS_INIT(NULL, 0, NULL, &encoder_timestamp_callback, NULL);
    MTE_SET_ENC_IO(e_args, text_to_send, text_length, encoded);
    g_encoder_status = mte_flen_enc_encode(g_encoder, &e_args);
#endif

    if (g_encoder_status != mte_status_success)
    {
      fprintf(stderr, "Error encoding: Status: %s/%s\n",
        mte_base_status_name(g_encoder_status),
        mte_base_status_description(g_encoder_status));
      fprintf(stderr, "Socket client closed due to encoding error.\n");
      return g_encoder_status;
    }

    //
    // For demonstration purposes only to show packets
    size_t base64_encoded_bytes = mte_base64_encode_bytes(e_args.bytes);
    char* base64_buffer;
    base64_buffer = malloc(base64_encoded_bytes);
    mte_base64_encode(e_args.encoded, e_args.bytes, base64_buffer);
    printf("Base64 encoded representation of the packet being sent: %s\n", base64_buffer);
    free(base64_buffer);

    //
    // Get the length of the packet to send.
    union bytes_length to_send_len_bytes;
    to_send_len_bytes.length = e_args.bytes;

    //
    // Check if little Endian and reverse if no - all sent in Big Endian
    if (LITTLE_ENDIAN == test_byte_order())
    {
      int size = sizeof(to_send_len_bytes.byte_array);
      for (int i = 0; i < size / 2; i++)
      {
        char temp = to_send_len_bytes.byte_array[i];
        to_send_len_bytes.byte_array[i] = to_send_len_bytes.byte_array[size - 1 - i];
        to_send_len_bytes.byte_array[size - 1 - i] = temp;
      }
    }

    //
    // Send the length-prefix
    size_t res = send_data(to_send_len_bytes.byte_array, sizeof(to_send_len_bytes.byte_array));
    if (res <= 0)
    {
      printf("Send failed.");
      close_socket();
      return 1;
    }

    //
    // Send the actual message
    res = send_data(e_args.encoded, e_args.bytes);
    if (res <= 0)
    {
      printf("Send failed.");
      close_socket();
      return 1;
    }

    // Receive the response from the remote device
    //
    // First get the length-prefix
    union bytes_length to_recv_len_bytes;
    res = (size_t)(recv_data(to_recv_len_bytes.byte_array, 4));
    if (LITTLE_ENDIAN == test_byte_order())
    {
      int size = sizeof(to_recv_len_bytes.byte_array);
      for (int i = 0; i < size / 2; i++)
      {
        char temp = to_recv_len_bytes.byte_array[i];
        to_recv_len_bytes.byte_array[i] = to_recv_len_bytes.byte_array[size - 1 - i];
        to_recv_len_bytes.byte_array[size - 1 - i] = temp;
      }
    }

    /* Step 12 Continue */
    // Decode incoming message and check for successful response
    res = (size_t)(recv_data(recv_buf, to_recv_len_bytes.length));

#if defined USE_MTE_CORE || defined USE_FLEN_ADDON
    char* decoded = MTE_ALLOCA(mte_dec_buff_bytes(g_decoder, to_recv_len_bytes.length));
    mte_dec_args d_args = MTE_DEC_ARGS_INIT(NULL, 0, NULL, &decoder_timestamp_callback, NULL);
    MTE_SET_DEC_IO(d_args, recv_buf, to_recv_len_bytes.length, decoded);
    g_decoder_status = mte_dec_decode(g_decoder, &d_args);
#endif
#if defined USE_MKE_ADDON
    char* decoded = MTE_ALLOCA(mte_mke_dec_buff_bytes(g_decoder, to_recv_len_bytes.length));
    mte_dec_args d_args = MTE_DEC_ARGS_INIT(NULL, 0, NULL, &decoder_timestamp_callback, NULL);
    MTE_SET_DEC_IO(d_args, recv_buf, to_recv_len_bytes.length, decoded);
    g_decoder_status = mte_mke_dec_decode(g_decoder, &d_args);
#endif

    if (g_decoder_status != mte_status_success)
    {
      fprintf(stderr, "Error decoding: Status: %s/%s\n",
        mte_base_status_name(g_decoder_status),
        mte_base_status_description(g_decoder_status));
      fprintf(stderr, "Socket client closed due to decoding error.\n");
      return g_decoder_status;
    }

    //
    // Convert byte array to string to view in console (this step is for display purposes)
    base64_encoded_bytes = mte_base64_encode_bytes(to_recv_len_bytes.length);
    base64_buffer = "";
    base64_buffer = malloc(base64_encoded_bytes);
    size_t base64_encoded_size = mte_base64_encode(recv_buf, to_recv_len_bytes.length, base64_buffer);
    if (base64_encoded_size > 0)
    {
      printf("Base64 encoded representation of the received packet: %s\n", base64_buffer);
    }
    free(base64_buffer);
  }

  // shutdown the connection since no more data will be sent
  close_socket();

  printf("Program stopped.");

  return 0;
}

static int test_byte_order() {
  short int word = 0x0001;
  char* b = (char*)&word;
  return (b[0] ? LITTLE_ENDIAN : BIG_ENDIAN);
}

/* Step 9 */
static mte_status encoder_entropy_input_callback(void* context, mte_drbg_ei_info* info)
{
  /* Create all-zero entropy for this demo. This should never be done in real
     applications. */
  (void)context;
  info->bytes = info->min_length;
  memset(info->buff, '0', info->min_length);
  return mte_status_success;
}

static mte_status decoder_entropy_input_callback(void* context, mte_drbg_ei_info* info)
{
  /* Create all-zero entropy for this demo. This should never be done in real
     applications. */
  (void)context;
  info->bytes = info->min_length;
  memset(info->buff, '0', info->min_length);
  return mte_status_success;
}

static void encoder_nonce_callback(void* context, mte_drbg_nonce_info* info)
{
  /* Create all-zero nonce for this demo. This should never be done in real
     applications. */
  (void)context;
  info->bytes = info->min_length;
  memset(info->buff, 0, info->min_length);
  *(int*)info->buff = g_encoder_nonce;
}

static void decoder_nonce_callback(void* context, mte_drbg_nonce_info* info)
{
  /* Create all-zero nonce for this demo. This should never be done in real
     applications. */
  (void)context;
  info->bytes = info->min_length;
  memset(info->buff, 0, info->min_length);
  *(int*)info->buff = g_decoder_nonce;
}

static uint64_t encoder_timestamp_callback(void* context)
{
  /* Return 0 for the timestamp. Real applications would request an actual
     timestamp as appropriate for their system. */
  (void)context;
  return 0;
}

static uint64_t decoder_timestamp_callback(void* context)
{
  /* Return 0 for the timestamp. Real applications would request an actual
     timestamp as appropriate for their system. */
  (void)context;
  return 0;
}

static int create_socket()
{
#if defined _WIN32
  long RESPONSE;
  struct WSAData WinSockData;
  WORD DLLVERSION = MAKEWORD(2, 1);
  RESPONSE = WSAStartup(DLLVERSION, &WinSockData);
  if (RESPONSE != 0)
  {
    return 0;
  }
#endif
  m_sock = (int32_t)socket(AF_INET, SOCK_STREAM, 0);

  if (!is_socket_valid())
  {
    return 0;
  }

  int32_t on = 1;
  if (setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on)) == -1)
  {
    return 0;
  }

  return 1;
}

static void close_socket()
{
  if (is_socket_valid())
  {
#if defined _WIN32
    closesocket(m_sock);
#else
    close(m_sock);
#endif

  }
}

static int is_socket_valid()
{
  return m_sock != -1;
}

static size_t send_data(const char* data, uint32_t data_size)
{
  size_t status = send(m_sock, data, data_size, 0);
  if (status == -1)
  {
    return 0;
  }
  else
  {
    return status;
  }
}

static size_t recv_data(char* data, uint32_t data_size)
{
  size_t char_count = recv(m_sock, data, data_size, 0);

  return char_count;
}

static int connect_socket(const char* host, uint16_t port)
{
  if (!is_socket_valid())
  {
    return 0;
  }

  m_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  m_addr.sin_family = AF_INET;
  m_addr.sin_port = htons(port);

  int32_t status = inet_pton(AF_INET, host, &m_addr.sin_addr);

  status = connect(m_sock, (struct sockaddr*)&m_addr, sizeof(m_addr));
  if (status == 0)
  {
    return 1;
  }
  else
  {
    return 0;
  }
}