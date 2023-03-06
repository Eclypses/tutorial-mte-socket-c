

<img src="Eclypses.png" style="width:50%;margin-right:0;"/>

<div align="center" style="font-size:40pt; font-weight:900; font-family:arial; margin-top:300px; " >
C Socket Tutorial</div>
<br>
<div align="center" style="font-size:28pt; font-family:arial; " >
MTE Implementation Tutorial (MTE Core, MKE, MTE Fixed Length)</div>
<br>
<div align="center" style="font-size:15pt; font-family:arial; " >
Using MTE version 3.0.x</div>





[Introduction](#introduction)

[Socket Tutorial Server and Client](#socket-tutorial-server-and-client)


<div style="page-break-after: always; break-after: page;"></div>

# Introduction

This tutorial is sending messages via a socket connection. This is only a sample, the MTE does NOT require the usage of sockets, you can use whatever communication protocol that is needed.

This tutorial demonstrates how to use Mte Core, Mte MKE and Mte Fixed Length. Depending on what your needs are, these three different implementations can be used in the same application OR you can use any one of them. They are not dependent on each other and can run simultaneously in the same application if needed.

The SDK that you received from Eclypses may not include the MKE or MTE FLEN add-ons. If your SDK contains either the MKE or the Fixed Length add-ons, the name of the SDK will contain "-MKE" or "-FLEN". If these add-ons are not there and you need them please work with your sales associate. If there is no need, please just ignore the MKE and FLEN options.

Here is a short explanation of when to use each, but it is encouraged to either speak to a sales associate or read the dev guide if you have additional concerns or questions.

***MTE Core:*** This is the recommended version of the MTE to use. Unless payloads are large or sequencing is needed this is the recommended version of the MTE and the most secure.

***MTE MKE:*** This version of the MTE is recommended when payloads are very large, the MTE Core would, depending on the token byte size, be multiple times larger than the original payload. Because this uses the MTE technology on encryption keys and encrypts the payload, the payload is only enlarged minimally.

***MTE Fixed Length:*** This version of the MTE is very secure and is used when the resulting payload is desired to be the same size for every transmission. The Fixed Length add-on is mainly used when using the sequencing verifier with MTE. In order to skip dropped packets or handle asynchronous packets the sequencing verifier requires that all packets be a predictable size. If you do not wish to handle this with your application then the Fixed Length add-on is a great choice. This is ONLY an encoder change - the decoder that is used is the MTE Core decoder.

In this tutorial we are creating an MTE Encoder and an MTE Decoder in the server as well as the client because we are sending secured messages in both directions. This is only needed when there are secured messages being sent from both sides, the server as well as the client. If only one side of your application is sending secured messages, then the side that sends the secured messages should have an Encoder and the side receiving the messages needs only a Decoder.

These steps should be followed on the server side as well as on the client side of the program.

**IMPORTANT**
>Please note the solution provided in this tutorial does NOT include the MTE library or supporting MTE library files. If you have NOT been provided an MTE library and supporting files, please contact Eclypses Inc. The solution will only work AFTER the MTE library and MTE library files have been incorporated.
  

# Socket Tutorial Server and Client

<ol>
<li>Copy the include directory from the mte-Windows or mte-Linux package (as appropriate) to both SocketClient and SocketServer directories.</li>
<br>
<li>Copy the lib directory from the mte-Windows or mte-Linux package (as appropriate) to both SocketClient and SocketServer directories.</li>

<br>
<li>Update the SocketClient and SocketServer project settigs with the following:
<ul>
<li>The addional include directories will need to add <b><i>include</i></b> as an entry.</li>
<li>The addional library directories will need to add <b><i>lib</i></b> as an entry.</li>
<li>The additonal dependiencies will need to add <b><i>mte.lib;</i></b> (Windows) / library dependiencies will need to add <b><i>mte;</i></b> (Linux) as an entry.</li>
</ul>
</li>
<br>
<li>Ensure that the dynamic libraries will be in the expected directory when the executable will run.</li> 
<ol type="a">
<li>For Windows, one way this can be done is to set in a post-build event command in each project with:</li>

```batchfile
xcopy /y /d  "$(ProjectDir)lib\mte.dll" "$(OutDir)"
```
This will copy the dynamic library to the same directory as the executable after it is built.
<li>For Linux, add the libmte.so file to each project. Additionally, it may need to be copied to a directory set in the environment path <code>LD_LIBRARY_PATH</code>, or in common shared library paths such as <code>/usr/lib/</code> and <code>/usr/local/lib/</code>.</li>
</ol> 
<br>
<li>(Optional)Add preprocessor directives to more easily handle the function calls for the MTE Core or the add-on configurations. Uncomment 'USE_MTE_CORE' to utilize the main MTE Core functions; uncomment 'USE_MKE_ADDON' to use the MTE MKE add-on functions; and uncomment 'USE_FLEN_ADDON' to use the Fixed length add-on functions.</li>

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
<li>Add include statements for both the MTE Encoder and MTE Decoder near the beginning of the main.c files (SocketClient And SocketServer).</li>

```c
#if !defined mte_alloca_h
#include "mte_alloca.h"
#endif
#if !defined mte_license_h
#include "mte_license.h"
#endif
#if !defined mte_init_h
#include "mte_init.h"
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
```
<li>Initialize the MTE.</li>

```c
if (!mte_init(NULL, NULL))
{
  fprintf(stderr, "MTE init error.");
  return -1;
}
```
<li>Create the MTE Decoder and MTE Encoder as well as the accompanying MTE status for each as global variables.</li>

***IMPORTANT NOTE***
>If using the fixed length MTE (FLEN), all messages that are sent that are longer than the set fixed length will be trimmed by the MTE. The other side of the MTE will NOT contain the trimmed portion. Also messages that are shorter than the fixed length will be padded by the MTE so each message that is sent will ALWAYS be the same length. When shorter message are "decoded" on the other side the MTE takes off the extra padding when using strings and hands back the original shorter message, BUT if you use the raw interface the padding will be present as all zeros. Please see official MTE Documentation for more information.

```c
MTE_HANDLE g_decoder;
mte_status g_decoder_status;
MTE_HANDLE g_encoder;
mte_status g_encoder_status;

```

<li>Next, we need to be able to set the entropy, nonce, and personalization/identification values.</li>
These values should be treated like encryption keys and never exposed. For demonstration purposes in the tutorial we are setting these values in the code. In a production environment these values should be protected and not available to outside sources. For the entropy, we can use a callback function that will get called during initiation. This function will give us the minimum and maximum values we can assign to entropy. A code sample below is included to demonstrate how to get these values.

```c
static mte_status encoder_entropy_input_callback(void* context, mte_drbg_ei_info* info)
{
  /* Create all-zero entropy for this demo. This should never be done in real
     applications. */
  (void)context;
  info->bytes = info->min_length;
  memset(info->buff, '0', info->min_length);
  return mte_status_success;
}
```
To assign values to the nonce and the personalization/identifier variables we are simply adding our default values as global variables to the top of the class.

```c

// OPTIONAL!!! adding 1 to decoder nonce so return value changes -- same nonce can be used for encoder and decoder
// on client side values will be switched so they match up encoder to decoder and vice versa
int g_encoder_nonce = 0;
int g_decoder_nonce = 1;
char* g_personal = "demo";
```
The nonce itself will be set in a similar manner to entropy within a callback function.
```c
static void encoder_nonce_callback(void* context, mte_drbg_nonce_info* info)
{
  /* Create all-zero nonce for this demo. This should never be done in real
     applications. */
  (void)context;
  info->bytes = info->min_length;
  memset(info->buff, 0, info->min_length);
  *(int*)info->buff = g_encoder_nonce;
}
```



<li>To ensure the MTE library is licensed correctly, run the license check. To ensure the DRBG is set up correctly, run the DRBGS self test. The LicenseCompanyName, and LicenseKey below should be replaced with your company’s MTE license information provided by Eclypses. If a trial version of the MTE is being used any value can be passed into those fields and it will work.</li>

```c
// Initialize MTE license. If a license code is not required (e.g., trial
// mode), this can be skipped. This demo attempts to load the license info
// from the environment if required.
if (!mte_license_init("Eclypses Inc", "Eclypses123"))
  {
    fprintf(stderr, "License init error (%s): %s\n",
      mte_base_status_name(mte_status_license_error),
      mte_base_status_description(mte_status_license_error));
    return mte_status_license_error;
  }
```

<li>Create MTE Decoder instances and MTE Encoder instances.</li>

```c
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
```

<li>Finally, we need to add the MTE calls to encode and decode the messages that we are sending and receiving from the other side. (Ensure on the client side the Encoder is used to encode the outgoing text, then the Decoder is used to decode the incoming response.)</li>

<br>
Here is a sample of how to do this on the Client Side.

```c
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
// Decode incoming message and check for successful response
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

```
<br>
Here is a sample of how to do this on the Server Side.

```c
//
// Decode received bytes and check to ensure successful result
#if defined USE_MTE_CORE || defined USE_FLEN_ADDON  
    char* decoded_text = MTE_ALLOCA(mte_dec_buff_bytes(g_decoder, to_recv_len_bytes.length));
    mte_dec_args d_args = MTE_DEC_ARGS_INIT(NULL, 0, NULL, &decoder_timestamp_callback, NULL);
    MTE_SET_DEC_IO(d_args, recv_buf, to_recv_len_bytes.length, decoded_text);
    g_decoder_status = mte_dec_decode(g_decoder, &d_args);
#endif
#if defined USE_MKE_ADDON
    char* decoded_text = MTE_ALLOCA(mte_mke_dec_buff_bytes(g_decoder, to_recv_len_bytes.length));
    mte_dec_args d_args = MTE_DEC_ARGS_INIT(NULL, 0, NULL, &decoder_timestamp_callback, NULL);
    MTE_SET_DEC_IO(d_args, recv_buf, to_recv_len_bytes.length, decoded_text);
    g_decoder_status = mte_mke_dec_decode(g_decoder, &d_args);
#endif

    if (g_decoder_status != mte_status_success)
    {
      fprintf(stderr, "Error decoding: Status: %s/%s\n",
        mte_base_status_name(g_decoder_status),
        mte_base_status_description(g_decoder_status));
      fprintf(stderr, "Socket server closed due to decoding error, press ENTER to end this...\n");
      return g_decoder_status;
    }
	
//
// Encode returning text and ensure successful
#if defined USE_MTE_CORE
    char* encoded_return = MTE_ALLOCA(mte_enc_buff_bytes(g_encoder, text_length));
    mte_enc_args e_args = MTE_ENC_ARGS_INIT(NULL, 0, NULL, &encoder_timestamp_callback, NULL);
    MTE_SET_ENC_IO(e_args, text_to_send, text_length, encoded_return);
    g_encoder_status = mte_enc_encode(g_encoder, &e_args);
#endif
#if defined USE_MKE_ADDON
    char* encoded_return = MTE_ALLOCA(mte_mke_enc_buff_bytes(g_encoder, text_length));
    mte_enc_args e_args = MTE_ENC_ARGS_INIT(NULL, 0, NULL, &encoder_timestamp_callback, NULL);
    MTE_SET_ENC_IO(e_args, text_to_send, text_length, encoded_return);
    g_encoder_status = mte_mke_enc_encode(g_encoder, &e_args);
#endif
#if defined USE_FLEN_ADDON
    char* encoded_return = MTE_ALLOCA(mte_flen_enc_buff_bytes(g_encoder));
    mte_enc_args e_args = MTE_ENC_ARGS_INIT(NULL, 0, NULL, &encoder_timestamp_callback, NULL);
    MTE_SET_ENC_IO(e_args, text_to_send, text_length, encoded_return);
    g_encoder_status = mte_flen_enc_encode(g_encoder, &e_args);
#endif

    if (g_encoder_status != mte_status_success)
    {
      fprintf(stderr, "Error encoding: Status: %s/%s\n",
        mte_base_status_name(g_encoder_status),
        mte_base_status_description(g_encoder_status));
      fprintf(stderr, "Socket server closed due to encoding error, press ENTER to end this...\n");
      return g_encoder_status;
    }

```
</ol>

***The Server side and the Client side of the MTE Sockets tutorial should now be ready for use on your device.***


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