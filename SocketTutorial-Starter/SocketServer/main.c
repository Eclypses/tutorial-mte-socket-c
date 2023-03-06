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

#if defined _WIN32
#define WIN32_LEAN_AND_MEAN

#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

// Need to link with Ws2_32.lib
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

#define DEFAULT_BUFLEN 2048
#define DEFAULT_PORT "27015"

static int test_byte_order();

static int create_socket();

static void close_socket();

static int is_socket_valid();

static int bind_socket(int port);

static int listen_socket();

static int accept_socket(char* port);

static size_t send_data(const char* data, uint32_t data_size);

static size_t recv_data(char* data, uint32_t data_size);

int32_t m_sock = -1;
int32_t s_sock = -1;
struct sockaddr_in m_addr;
struct sockaddr_in rm_addr;
struct hostent* hp;

union bytes_length
{
  uint32_t length;
  char byte_array[4];
};

int main(int argc, char** argv)
{
  //
  // This tutorial uses Sockets for communication.
  // It should be noted that the MTE can be used with any type of communication. (SOCKETS are not required!)
  //

  printf("Starting C Socket Server.\n");

  printf("Please enter port to use, press Enter to use default: %s\n", DEFAULT_PORT);
  char port[10];
  fflush(stdout);
  (void)!fgets(port, sizeof(port[0]), stdin);
  port[strcspn(port, "\r\n")] = 0;
  if (strlen(port) == 0)
  {
    memcpy(port, DEFAULT_PORT, sizeof(DEFAULT_PORT));
  }

  memset(&m_addr, 0, sizeof(m_addr));
  memset(&rm_addr, 0, sizeof(rm_addr));

  char recv_buf[DEFAULT_BUFLEN];

  printf("Listening for a new Client connection...\n");

  int socket_creation = create_socket();
  if (socket_creation == 0)
  {
    printf("Unable to create socket.");
    return socket_creation;
  }

  int socket_binding = bind_socket(atoi(port));
  if (socket_binding == 0)
  {
    printf("Unable to bind to socket.");
    return socket_binding;
  }

  int socket_listening = listen_socket();
  if (socket_listening == 0)
  {
    printf("Unable to listen to socket.");
    return socket_listening;
  }

  int socket_accepting = accept_socket(port);
  if (socket_accepting == 0)
  {
    printf("Unable to accept the socket.");
    return socket_accepting;
  }

  printf("Connected with Client.\n");

  // Receive until the peer shuts down the connection
  while (1)
  {
    printf("Listening from messages from Client...\n");

    //
    // Get the length of bytes coming in
    union bytes_length to_recv_len_bytes;
    size_t res = recv_data(to_recv_len_bytes.byte_array, 4);
    if (res == 0)
    {
      break;
    }

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
    if (to_recv_len_bytes.length == 0)
    {
      break;
    }

    //
    // Get the full message based on length of bytes coming in   
    res = recv_data(recv_buf, to_recv_len_bytes.length);

    char* recv_text = recv_buf;
    recv_text[to_recv_len_bytes.length] = '\0';

    //
    // For demonstration purposes only to show received packet.   
    printf("The received packet: %s\n", recv_text);

    union bytes_length to_send_len_bytes;
    to_send_len_bytes.length = (uint32_t)strlen(recv_text);

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
    // For demonstration purposes only to show packets
    printf("The packet being sent: %s\n", recv_text);   

    //
    // Send the length of the message
    res = send_data(to_send_len_bytes.byte_array, sizeof(to_send_len_bytes.byte_array));

    //
    // Send encoded message
    res = send_data(recv_text, (uint32_t)strlen(recv_text));
  }

  // shutdown the connection since we're done
  close_socket();

  printf("Program stopped.");

  return 0;
}

static int test_byte_order() {
  short int word = 0x0001;
  char* b = (char*)&word;
  return (b[0] ? LITTLE_ENDIAN : BIG_ENDIAN);
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

  // TIME_WAIT - argh
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

static int bind_socket(int port)
{
  if (!is_socket_valid())
  {
    return 0;
  }

  m_addr.sin_family = AF_INET;
  m_addr.sin_addr.s_addr = INADDR_ANY;
  m_addr.sin_port = htons((uint16_t)port);

  int32_t bind_return = bind(m_sock, (struct sockaddr*)&m_addr, sizeof(m_addr));

  if (bind_return == -1)
  {
    return 0;
  }
  return 1;
}

static int listen_socket()
{
  if (!is_socket_valid())
  {
    return 0;
  }

  int32_t listen_return = listen(m_sock, 1);

  if (listen_return == -1)
  {
    return 0;
  }

  return 1;
}

static int accept_socket(char* port)
{
  struct sockaddr_in client_addr;
  socklen_t slen = sizeof(client_addr);
  s_sock = (int32_t)accept(m_sock, (struct sockaddr*)&client_addr, &slen);
  if (s_sock == 0)
  {
    return 0;
  }
  printf("Socket Server is listening on %s : port %s\n", inet_ntoa(client_addr.sin_addr), port);
  return 1;
}

static size_t send_data(const char* data, uint32_t data_size)
{
  size_t status = send(s_sock, data, data_size, 0);
  if (status == -1)
  {
    return 0;
  }
  else
  {
    return status;
  }
}

static size_t recv_data(char data[], uint32_t data_size)
{
  size_t char_count = (size_t)recv(s_sock, data, data_size, 0);

  return char_count;
}