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

#include "socket_manager.h"

int32_t m_sock = -1;
struct sockaddr_in m_addr;
struct sockaddr_in rm_addr;
struct hostent* hp;

/// <summary>
/// Determines if the socket is valid.
/// </summary>
/// <returns>True if socket is valid.</returns>
static bool is_socket_valid();

int create_socket()
{
  memset(&m_addr, 0, sizeof(m_addr));
  memset(&rm_addr, 0, sizeof(rm_addr));

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
  m_sock = (int32_t)socket(AF_INET, SOCK_STREAM, 6);

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

int connect_socket(const char* host, uint16_t port)
{
  if (!is_socket_valid())
  {
    return 0;
  }

  m_addr.sin_addr.s_addr = inet_addr(host);
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

void close_socket()
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

size_t send_message(const char header, const char* message, size_t message_bytes)
{
  // Create a union to be able to set the length as a simple size.
  // Then the char array will automatically be set and
  // ready to be sent to the other side, possibly needing to reverse
  // depending on Endianess.
  union bytes_length
  {
    uint32_t length;
    char byte_array[5];
  };

  // Get the length of the packet to send.
  union bytes_length to_send_len_bytes;
  to_send_len_bytes.length = (uint32_t)(message_bytes);

  // Check if little Endian and reverse if no - all sent in Big Endian.
  if (LITTLE_ENDIAN)
  {
    int size = sizeof(to_send_len_bytes.length);
    for (int i = 0; i < size / 2; i++)
    {
      char temp = to_send_len_bytes.byte_array[i];
      to_send_len_bytes.byte_array[i] = to_send_len_bytes.byte_array[size - 1 - i];
      to_send_len_bytes.byte_array[size - 1 - i] = temp;
    }
  }
  // Put the header byte into 5th byte
  to_send_len_bytes.byte_array[4] = header;


  // Send the message size as big-endian and the header byte.
  size_t res = (size_t)(send(m_sock, to_send_len_bytes.byte_array, sizeof(to_send_len_bytes.byte_array), 0));
  if (res < sizeof(to_send_len_bytes.byte_array))
  {
    printf("Sending the message size failed.");
    close_socket();
    return 0;
  }

  // Send the actual message.
  // Chunk the message into chunks.
  res = 0;
  size_t bytes_sent = 0;
  while (res < message_bytes)
  {
    size_t sending_size = message_bytes - res;
    if (CHUNK_BYTES < sending_size)
    {
      sending_size = CHUNK_BYTES;
    }

    bytes_sent = (size_t)send(m_sock, message + res, (int)sending_size, 0);
    if (bytes_sent == 0)
    {
      // No bytes were sent;
      return 0;
    }
    res += bytes_sent;
  }

  if (res < message_bytes)
  {
    printf("Sending the message failed.");
    close_socket();
    return 0;
  }

  return res;
}

struct recv_msg receive_message()
{
  // Create recv_msg struct.
  struct recv_msg msg_struct;
  msg_struct.success = false;
  msg_struct.header = '\0';
  msg_struct.message.data = NULL;
  msg_struct.message.size = 0;

  // Create a union to be able to get the char array from the Client.
  // It may need to be reversed depending on Endianess.
  // Then the length will have already been set.
  union bytes_length
  {
    uint32_t length;
    char byte_array[5];
  };

  // Create an array to hold the message size coming in.
  union bytes_length to_recv_len_bytes;
  if (!recv_data(to_recv_len_bytes.byte_array, sizeof(to_recv_len_bytes.byte_array)))
    return msg_struct;

  // Check if little Endian and reverse if no - all received in Big Endian.
  if (LITTLE_ENDIAN)
  {
    int size = sizeof(to_recv_len_bytes.length);
    for (int i = 0; i < size / 2; i++)
    {
      char temp = to_recv_len_bytes.byte_array[i];
      to_recv_len_bytes.byte_array[i] = to_recv_len_bytes.byte_array[size - 1 - i];
      to_recv_len_bytes.byte_array[size - 1 - i] = temp;
    }
  }

  // Get the header byte from the 5th byte
  msg_struct.header = to_recv_len_bytes.byte_array[4];

  // Receive the message from the Client.
  msg_struct.message.data = malloc(to_recv_len_bytes.length);
  if (!recv_data(msg_struct.message.data, to_recv_len_bytes.length))
    return  msg_struct;

  // The size will be the rest of the message.
  msg_struct.message.size = to_recv_len_bytes.length;

  // Set status to true;
  msg_struct.success = true;

  return msg_struct;
}

static bool is_socket_valid()
{
  return m_sock != -1;  
}

static bool recv_data(uint8_t* data, size_t bytes_needed)
{
  size_t res = 0;
  size_t bytes_read = 0;
  while (res < bytes_needed)
  {
    size_t receiving_size = bytes_needed - res;
    if (CHUNK_BYTES < receiving_size)
    {
      receiving_size = CHUNK_BYTES;
    }

    bytes_read = (size_t)recv(m_sock, data + res, (int)receiving_size, 0);
    if (bytes_read == 0)
    {
      // No bytes were received;
      return false;
    }
    res += bytes_read;
  }

  if (res < bytes_needed)
  {
    printf("Receiving the message failed.");
    close_socket();
    return false;
  }

  return true;
}