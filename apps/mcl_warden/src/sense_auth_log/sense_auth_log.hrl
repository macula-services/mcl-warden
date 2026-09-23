%%% The auth-log sensor's state. In a header so the rotation tests can read it
%%% by field name instead of by tuple position — following a log across
%%% rotation is the part of this sensor that has actually failed in production,
%%% so it is the part that has to stay pinned.
-record(st, {path :: string(),
             fd :: file:io_device() | undefined,
             %% Inode of the file behind `fd'. What rotation changes at the
             %% path, and the only thing that reliably reveals it.
             inode :: non_neg_integer() | undefined,
             pos = 0 :: non_neg_integer(),
             %% When we last consumed bytes from the log. `undefined' means we
             %% have not read a single byte since boot, which is different from
             %% having gone quiet and is treated differently by health/0: a
             %% warden that has never seen traffic may simply be on a quiet box,
             %% but one that WAS reading and then stopped is blind.
             last_read_ms :: integer() | undefined,
             %% ip => [timestamp_ms] within the window
             hits = #{} :: #{binary() => [integer()]},
             %% ip => last_reported_ms
             reported = #{} :: #{binary() => integer()},
             %% ip => set of usernames tried (evidence; revealing)
             users = #{} :: #{binary() => [binary()]}}).
