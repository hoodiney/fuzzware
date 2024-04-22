int __fastcall rcm_receive_message_check_len_insecure()
{
  unsigned int v0; // r5
  unsigned int v1; // r4
  char *v2; // r7
  _DWORD *v3; // r0
  int v4; // r1
  unsigned int v5; // r6
  unsigned int v6; // r6
  int v7; // r0
  int v8; // r0
  main_populated_table *callback_table; // [sp+4h] [bp-2Ch]
  char (*src)[16384]; // [sp+8h] [bp-28h]
  unsigned int n; // [sp+Ch] [bp-24h] BYREF
  BOOL v13; // [sp+10h] [bp-20h]
  int v14; // [sp+14h] [bp-1Ch]
  _DWORD *i; // [sp+18h] [bp-18h]

  v0 = 0; // total_rxd
  v1 = 1024; // record the amount of bytes newly received
  v2 = (char *)&rcm_msg_buf;
  n = 0;
  v14 = 1;
  callback_table = usb_get_callback_table();
  v3 = &g_rcm_state;
  for ( i = &g_rcm_state; ; v3 = i )
  {
    v4 = v3[7] ^ 1;
    i[7] = v4;
    v13 = v1 > n;
    if ( v1 > n )
      thumb_thunk_2args((int)usb_buffers[v4], 0x4000, (int)callback_table->read_ep1_out);
    v5 = n;
    src = usb_buffers[i[7] ^ 1]; // here "src" is the buffer that received data last time.
    if ( n && v0 < 0x2A8 )
    {
      if ( 680 - v0 < n )
        v5 = 680 - v0;
      memcpy_libc_thumb(v2, src, v5); // dst:v2, cnt:v5
      v2 += v5;
      src = (char (*)[16384])((char *)src + v5);
      v0 += v5;
      n -= v5;
      v1 -= v5;
      if ( v0 == 680 )
        v2 = rcm_extra_data;
      if ( v14 && v0 >= 4 )
      {
        if ( rcm_msg_buf.len_insecure >= 0x302A8u
          || rcm_msg_buf.len_insecure < 0x400u
          || (rcm_msg_buf.len_insecure & 0xF) != 8 )
        {
          v7 = 8;
          goto LABEL_20;
        }
        v1 = rcm_msg_buf.len_insecure - v0;
        v14 = 0;
      }
    }
    v6 = v1;
    if ( v1 >= n )
      v6 = n;
    memcpy_libc_thumb(v2, src, v6);
    v2 += v6; // move v2 to the next to-be-written address on rcm_msg_buf
    v0 += v6; // total_rxd += v6
    v1 -= v6; // 
    n -= v6;
    if ( n )
    {
      v7 = 15;
LABEL_20:
      rcm_error_and_reset_ep1(v7);
      goto LABEL_21;
    }
    if ( v13 )
    {
      v8 = thumb_thunk_3args(&n, -1, usb_buffers[i[7]], callback_table->get_ep1_out_recvd_bytes); // "callback_table->get_ep1_out_recvd_bytes" is "usb_device_ep1_get_bytes_readable"
      if ( v8 == 28 )
        goto LABEL_21;
      if ( v8 )
      {
        rcm_error_and_reset_ep1(12);
LABEL_21:
        JUMPOUT(0x102522);
      }
    }
    if ( !v1 )
      goto LABEL_21;
  }
}