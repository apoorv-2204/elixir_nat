defmodule Nat.Errors do
  @moduledoc """
  Defines module wide errors
  """
  # An atom that is named from the POSIX error codes used in Unix, and in the runtime libraries of most C compilers.
  defmacro __using__(_) do
    quote do
      @type pmp_error() ::
              :unsupported_version
              | :not_authorized
              | :network_failure
              | :out_of_resources
              | :unsupported_opcode
              | :bad_response

      @posix [
        :eaddrinuse,
        :eaddrnotavail,
        :eafnosupport,
        :ealready,
        :econnaborted,
        :econnrefused,
        :econnreset,
        :edestaddrreq,
        :ehostdown,
        :ehostunreach,
        :einprogress,
        :eisconn,
        :emsgsize,
        :enetdown,
        :enetunreach,
        :enopkg,
        :enoprotoopt,
        :enotconn,
        :enotty,
        :enotsock,
        :eproto,
        :eprotonosupport,
        :eprototype,
        :esocktnosupport,
        :etimedout,
        :ewouldblock,
        :exbadport,
        :exbadseq
      ]

      @file_posix [
        :eacces,
        :eagain,
        :ebadf,
        :ebadmsg,
        :ebusy,
        :edeadlk,
        :edeadlock,
        :edquot,
        :eexist,
        :efault,
        :efbig,
        :eftype,
        :eintr,
        :einval,
        :eio,
        :eisdir,
        :eloop,
        :emfile,
        :emlink,
        :emultihop,
        :enametoolong,
        :enfile,
        :enobufs,
        :enodev,
        :enolck,
        :enolink,
        :enoent,
        :enomem,
        :enospc,
        :enosr,
        :enostr,
        :enosys,
        :enotblk,
        :enotdir,
        :enotsup,
        :enxio,
        :eopnotsupp,
        :eoverflow,
        :eperm,
        :epipe,
        :erange,
        :erofs,
        :espipe,
        :esrch,
        :estale,
        :etxtbsy,
        :exdev
      ]
    end
  end
end
