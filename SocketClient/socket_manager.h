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

#ifndef socket_manager_h
#define socket_manager_h

#include "globals.h"
#include "mtesupport_ecdh.h"
#include <stdbool.h>

struct recv_msg
{
  bool success;
  char header;
  byte_array message;
};

#ifdef __cplusplus
extern "C"
{
#endif

  /// <summary>
  /// Creates the socket.
  /// </summary>
  /// <returns>1 if socket was created, 0 otherwise.</returns>
  int create_socket();

  /// <summary>
  /// Connects to the socket.
  /// </summary>
  /// <param name="host">The host ip address.</param>
  /// <param name="port">The port.</param>
  /// <returns>1 if socket was connected, 0 otherwise.</returns>
  int connect_socket(const char* host, uint16_t port);

  /// <summary>
  /// Closes the socket.
  /// </summary>
  void close_socket();

  /// <summary>
  /// Sends the message through the socket.
  /// </summary>
  /// <param name="header">The header to go with the message.</param>
  /// <param name="message">The message to be sent.</param>
  /// <param name="message_bytes">The size of the message in bytes.</param>
  /// <returns>The number of bytes sent.</returns>
  size_t send_message(const char header, const char* message, size_t message_bytes);

  /// <summary>
  /// Receives the message through the socket.
  /// </summary>
  /// <returns>Struct that contains the message, message size in bytes, header, and success result.</returns>
  struct recv_msg receive_message();

  /// <summary>
  /// Determines if the socket is valid here.
  /// </summary>
  /// <returns>True if socket is valid.</returns>
  //static bool is_socket_valid();

  /// <summary>
  /// Receives data for the amount of bytes needed.
  /// </summary>
  /// <param name="data">The data to be received.</param>
  /// <param name="bytes_needed">The </param>
  /// <returns></returns>
  static bool recv_data(uint8_t* data, size_t bytes_needed);

#ifdef __cplusplus
}
#endif

#endif