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

#define DEFAULT_BUFLEN 2048
#define DEFAULT_PORT "27015"
#define DEFAULT_SERVER_IP "localhost"

/// <summary>
/// Determines the byte order (big endian or little endian).
/// </summary>
/// <returns></returns>
static int test_byte_order();

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
  (void)!fgets(port, sizeof(port[0]), stdin);
  port[strcspn(port, "\r\n")] = 0;
  if (strlen(port) == 0)
  {
    memcpy(port, DEFAULT_PORT, sizeof(DEFAULT_PORT));
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

    //
    // For demonstration purposes only to show packets
    printf("The packet being sent: %s\n", text_to_send);

    //
    // Get the length of the packet to send.
    union bytes_length to_send_len_bytes;
    to_send_len_bytes.length = (uint32_t)strlen(text_to_send);

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
    res = send_data(text_to_send, (uint32_t)strlen(text_to_send));
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

    char* recv_text = recv_buf;
    recv_text[to_recv_len_bytes.length] = '\0';
        
    // Show incoming message.
    res = (size_t)(recv_data(recv_buf, to_recv_len_bytes.length));
     
    printf("The received packet: %s\n", recv_text);    
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

static size_t recv_data(char data[], uint32_t data_size)
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