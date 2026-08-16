# C# Binding (P/Invoke)

This directory contains the planned C# binding surface. The native side is the
C ABI described in [`../c/p2p.h`](../c/p2p.h); a C# consumer can P/Invoke into
a shared library built from the Go core.

## Planned P/Invoke mapping

```csharp
[StructLayout(LayoutKind.Sequential)]
public delegate void P2pEventCallback(
    int eventId,
    [MarshalAs(UnmanagedType.LPUTF8Str)] string peerId,
    IntPtr data,
    nuint len,
    IntPtr userData);

[DllImport("p2p", CallingConvention = CallingConvention.Cdecl)]
public static extern IntPtr p2p_session_new(
    [MarshalAs(UnmanagedType.LPUTF8Str)] string server,
    [MarshalAs(UnmanagedType.LPUTF8Str)] string stun,
    [MarshalAs(UnmanagedType.LPUTF8Str)] string token,
    [MarshalAs(UnmanagedType.Bool)] bool enableTls,
    [MarshalAs(UnmanagedType.LPUTF8Str)] string tlsServerName,
    [MarshalAs(UnmanagedType.Bool)] bool tlsInsecureSkipVerify,
    P2pEventCallback cb,
    IntPtr userData);

[DllImport("p2p", CallingConvention = CallingConvention.Cdecl)]
public static extern int p2p_session_connect(IntPtr session,
    [MarshalAs(UnmanagedType.LPUTF8Str)] string room);

[DllImport("p2p", CallingConvention = CallingConvention.Cdecl)]
public static extern int p2p_session_send(IntPtr session,
    [MarshalAs(UnmanagedType.LPUTF8Str)] string peer,
    byte[] data, nuint len);

[DllImport("p2p", CallingConvention = CallingConvention.Cdecl)]
public static extern int p2p_session_broadcast(IntPtr session,
    byte[] data, nuint len);

[DllImport("p2p", CallingConvention = CallingConvention.Cdecl)]
public static extern void p2p_session_free(IntPtr session);
```

The actual native shared library (`libp2p.so` / `p2p.dll` / `libp2p.dylib`)
requires a cgo export layer and is not built in this repository yet.
