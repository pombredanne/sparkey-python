#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2012-2013 Spotify AB
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from cffi import FFI
from functools import partial

ffi = FFI()

ffi.cdef("""
typedef enum {
  SPARKEY_SUCCESS = 0,
  SPARKEY_INTERNAL_ERROR = -1,

  SPARKEY_FILE_NOT_FOUND = -100,
  SPARKEY_PERMISSION_DENIED = -101,
  SPARKEY_TOO_MANY_OPEN_FILES = -102,
  SPARKEY_FILE_TOO_LARGE = -103,
  SPARKEY_FILE_ALREADY_EXISTS = -104,
  SPARKEY_FILE_BUSY = -105,
  SPARKEY_FILE_IS_DIRECTORY = -106,
  SPARKEY_FILE_SIZE_EXCEEDED = -107,
  SPARKEY_FILE_CLOSED = -108,
  SPARKEY_OUT_OF_DISK = -109,
  SPARKEY_UNEXPECTED_EOF = -110,
  SPARKEY_MMAP_FAILED = -111,

  SPARKEY_WRONG_LOG_MAGIC_NUMBER = -200,
  SPARKEY_WRONG_LOG_MAJOR_VERSION = -201,
  SPARKEY_UNSUPPORTED_LOG_MINOR_VERSION = -202,
  SPARKEY_LOG_TOO_SMALL = -203,
  SPARKEY_LOG_CLOSED = -204,
  SPARKEY_LOG_ITERATOR_INACTIVE = -205,
  SPARKEY_LOG_ITERATOR_MISMATCH = -206,
  SPARKEY_LOG_ITERATOR_CLOSED = -207,
  SPARKEY_LOG_HEADER_CORRUPT = -208,
  SPARKEY_INVALID_COMPRESSION_BLOCK_SIZE = -209,
  SPARKEY_INVALID_COMPRESSION_TYPE = -210,

  SPARKEY_WRONG_HASH_MAGIC_NUMBER = -300,
  SPARKEY_WRONG_HASH_MAJOR_VERSION = -301,
  SPARKEY_UNSUPPORTED_HASH_MINOR_VERSION = -302,
  SPARKEY_HASH_TOO_SMALL = -303,
  SPARKEY_HASH_CLOSED = -304,
  SPARKEY_FILE_IDENTIFIER_MISMATCH = -305,
  SPARKEY_HASH_HEADER_CORRUPT = -306,
  SPARKEY_HASH_SIZE_INVALID = -307,

} sparkey_returncode;

const char * sparkey_errstring(sparkey_returncode code);

struct sparkey_logwriter;
typedef struct sparkey_logwriter sparkey_logwriter;

typedef enum {
  SPARKEY_COMPRESSION_NONE,
  SPARKEY_COMPRESSION_SNAPPY
} sparkey_compression_type;

typedef enum {
  SPARKEY_ENTRY_PUT,
  SPARKEY_ENTRY_DELETE
} sparkey_entry_type;

typedef enum {
  SPARKEY_ITER_NEW,
  SPARKEY_ITER_ACTIVE,
  SPARKEY_ITER_CLOSED,
  SPARKEY_ITER_INVALID
} sparkey_iter_state;

struct sparkey_logreader;
typedef struct sparkey_logreader sparkey_logreader;

struct sparkey_logiter;
typedef struct sparkey_logiter sparkey_logiter;

struct sparkey_hashreader;
typedef struct sparkey_hashreader sparkey_hashreader;

sparkey_returncode sparkey_logwriter_create(sparkey_logwriter **log, const char *filename, sparkey_compression_type compression_type, int compression_block_size);
sparkey_returncode sparkey_logwriter_append(sparkey_logwriter **log, const char *filename);
sparkey_returncode sparkey_logwriter_put(sparkey_logwriter *log, uint64_t keylen, const uint8_t *key, uint64_t valuelen, const uint8_t *value);
sparkey_returncode sparkey_logwriter_delete(sparkey_logwriter *log, uint64_t keylen, const uint8_t *key);
sparkey_returncode sparkey_logwriter_flush(sparkey_logwriter *log);
sparkey_returncode sparkey_logwriter_close(sparkey_logwriter **log);

/* logreader */

sparkey_returncode sparkey_logreader_open(sparkey_logreader **log, const char *filename);
void sparkey_logreader_close(sparkey_logreader **log);
uint64_t sparkey_logreader_maxkeylen(sparkey_logreader *log);
uint64_t sparkey_logreader_maxvaluelen(sparkey_logreader *log);
int sparkey_logreader_get_compression_blocksize(sparkey_logreader *log);
sparkey_compression_type sparkey_logreader_get_compression_type(sparkey_logreader *log);
sparkey_returncode sparkey_logiter_create(sparkey_logiter **iter, sparkey_logreader *log);
void sparkey_logiter_close(sparkey_logiter **iter);
sparkey_returncode sparkey_logiter_seek(sparkey_logiter *iter, sparkey_logreader *log, uint64_t position);
sparkey_returncode sparkey_logiter_skip(sparkey_logiter *iter, sparkey_logreader *log, int count);
sparkey_returncode sparkey_logiter_next(sparkey_logiter *iter, sparkey_logreader *log);
sparkey_returncode sparkey_logiter_reset(sparkey_logiter *iter, sparkey_logreader *log);
sparkey_returncode sparkey_logiter_keychunk(sparkey_logiter *iter, sparkey_logreader *log, uint64_t maxlen, uint8_t ** res, uint64_t *len);
sparkey_returncode sparkey_logiter_valuechunk(sparkey_logiter *iter, sparkey_logreader *log, uint64_t maxlen, uint8_t ** res, uint64_t *len);
sparkey_returncode sparkey_logiter_fill_key(sparkey_logiter *iter, sparkey_logreader *log, uint64_t maxlen, uint8_t *buf, uint64_t *len);
sparkey_returncode sparkey_logiter_fill_value(sparkey_logiter *iter, sparkey_logreader *log, uint64_t maxlen, uint8_t *buf, uint64_t *len);
sparkey_returncode sparkey_logiter_keycmp(sparkey_logiter *iter1, sparkey_logiter *iter2, sparkey_logreader *log, int *res);
sparkey_iter_state sparkey_logiter_state(sparkey_logiter *iter);
sparkey_entry_type sparkey_logiter_type(sparkey_logiter *iter);
uint64_t sparkey_logiter_keylen(sparkey_logiter *iter);
uint64_t sparkey_logiter_valuelen(sparkey_logiter *iter);

/* hashwriter */
sparkey_returncode sparkey_hash_write(const char *hash_filename, const char *log_filename, int hash_size);

/* hashreader */
sparkey_returncode sparkey_hash_open(sparkey_hashreader **reader, const char *hash_filename, const char *log_filename);
sparkey_logreader * sparkey_hash_getreader(sparkey_hashreader *reader);
void sparkey_hash_close(sparkey_hashreader **reader);
sparkey_returncode sparkey_hash_get(sparkey_hashreader *reader, const uint8_t *key, uint64_t keylen, sparkey_logiter *iter);
sparkey_returncode sparkey_logiter_hashnext(sparkey_logiter *iter, sparkey_hashreader *reader);
uint64_t sparkey_hash_numentries(sparkey_hashreader *reader);
uint64_t sparkey_hash_numcollisions(sparkey_hashreader *reader);

/* util */

char * sparkey_create_log_filename(const char *index_filename);
char * sparkey_create_index_filename(const char *log_filename);
""")

libsparkey = ffi.dlopen('sparkey')


# Some constants
class Compression(object):
    NONE = 0
    SNAPPY = 1


class IterState(object):
    NEW = 0
    ACTIVE = 1
    CLOSED = 2
    INVALID = 3


class IterType(object):
    PUT = 0
    DELETE = 1


class SparkeyException(Exception):
    pass


class LogWriter(object):
    def __init__(self, filename, mode='NEW',
                 compression_type=Compression.NONE, compression_block_size=0):
        """Creates or appends a log file.

        This is not threadsafe, don't write to the same file from
        multiple threads or processes.

        @param filename: file to create or append to.

        @param mode: one of two modes:
            - NEW: creates the file regardless of whether it
              already exists or not.
            - APPEND: appends to the log if it exists, otherwise
              raises an exception.

        @param compression_type: one of two types:
            - NONE: keys and values are written as is, and
              each key-value pair is considered a block of its own.
            - SNAPPY: compression is done on a block level of at most
              compression_block_size uncompressed bytes.

              Each block may contain multiple key/value pairs and it may split
              keys or values over block borders.

        @param compression_block_size: mandatory unless compression is
               NONE. This indicates how large the maximum block may be.

               To get good compression and performance, this should be a
               fairly small multiple of expected key + value size.

        """
        self._log = ffi.new("sparkey_logwriter **")
        if mode == 'NEW':
            libsparkey.sparkey_logwriter_create(self._log, filename,
                              compression_type,
                              compression_block_size)
        elif mode == 'APPEND':
            libsparkey.sparkey_logwriter_append(self._log, filename)
        else:
            raise SparkeyException("Invalid mode %s, expected 'NEW' or "
                                   "'APPEND'" % (mode))

    def __del__(self):
        self.close()

    def close(self):
        """Closes the writer (if not already closed).

        Also flushes all pending changes from memory to file.

        """
        if self._log is not None:
            libsparkey.sparkey_logwriter_close(self._log)
            self._log = None

    def _assert_open(self):
        if self._log is None:
            raise SparkeyException("Writer is closed")

    def flush(self):
        """Flushes all pending changes from memory to file."""
        self._assert_open()
        libsparkey.sparkey_logwriter_flush(self._log[0])

    def __setitem__(self, key, value):
        """Equivalent to put(key, value)"""
        self.put(key, value)

    def put(self, key, value):
        """Append the key-value pair to the log.

        @param key: must be a string
        @param value: must be a string

        """
        self._assert_open()
        if type(key) != str:
            raise SparkeyException("key must be a string")
        if type(value) != str:
            raise SparkeyException("value must be a string")
        libsparkey.sparkey_logwriter_put(self._log[0], len(key), key, len(value), value)

    def __delitem__(self, key):
        """del writer[key] is equivalent to delete(key) (see L{delete})"""
        self.delete(key)

    def delete(self, key):
        """Appends a delete operation of key to the log.

        @param key: must be a string

        """
        self._assert_open()
        if type(key) != str:
            raise SparkeyException("key must be a string")
        libsparkey.sparkey_logwriter_delete(self._log[0], len(key), key)


class LogReader(object):
    def __init__(self, filename):
        """Opens a file for log iteration.

        @param filename: file to open.

        """
        self._log = ffi.new("sparkey_logreader **")
        libsparkey.sparkey_logreader_open(self._log, filename)

    def __del__(self):
        self.close()

    def close(self):
        """Safely closes the log reader."""
        if self._log is not None:
            libsparkey.sparkey_logreader_close(self._log)
            self._log = None

    def __iter__(self):
        """Creates a new iterator for this log reader.

        @returntype: L{LogIter}

        """
        return LogIter(self)

    def _assert_open(self):
        if self._log is None:
            raise SparkeyException("Reader is closed")


def _iter_res(iterator, log):
    iterator_ = iterator[0]
    state = libsparkey.sparkey_logiter_state(iterator_)

    if state != IterState.ACTIVE:
        raise StopIteration()
    type_ = libsparkey.sparkey_logiter_type(iterator_)

    keylen = libsparkey.sparkey_logiter_keylen(iterator_)
    string_buffer = ffi.new("uint8_t*", keylen)
    length = ffi.new("uint64_t*")
    libsparkey.sparkey_logiter_fill_key(iterator_, log[0], keylen, string_buffer, length)

    if length[0] != keylen:
        raise SparkeyException("Invalid keylen, expected %s but got %s" %
                               (keylen, length[0]))
    key = ffi.string(string_buffer, length[0])

    value_len = libsparkey.sparkey_logiter_valuelen(iterator_)
    string_buffer = ffi.new("uint8_t*", value_len)
    libsparkey.sparkey_logiter_fill_value(iterator_, log[0], value_len, string_buffer, length)
    if length[0] != value_len:
        raise SparkeyException("Invalid value_len, expected %s but got %s" %
                               (value_len, length[0]))
    value = ffi.string(string_buffer, length[0])
    return key, value, type_


class LogIter(object):
    def __init__(self, logreader):
        """Internal function.

        Use iter(logreader) or just "for key, value, type in logreader:"
        instead.
        """
        logreader._assert_open()
        self._iter = ffi.new("sparkey_logiter**")
        self._log = logreader
        libsparkey.sparkey_logiter_create(self._iter, logreader._log[0])

    def __del__(self):
        self.close()

    def close(self):
        """Safely closes the iterator."""
        if self._iter is not None:
            libsparkey.sparkey_logiter_close(self._iter)
            self._iter = None

    def __iter__(self):
        return self

    def _assert_open(self):
        if self._iter is None or self._log is None:
            raise SparkeyException("Iterator is closed")
        self._log._assert_open()

    def next(self):
        """Return next element in the log.

        @return: (key, value, type) if there are remaining elements.
                 key and value are strings and type is a L{IterType}.

        @raise StopIteration: if there are no more entries in the log.

        """
        self._assert_open()
        libsparkey.sparkey_logiter_next(self._iter[0], self._log._log[0])
        return _iter_res(self._iter, self._log._log)


def writehash(hashfile, logfile, hash_size=0):
    """Write a hash file based on the contents in the log file.

    If the log file hasn't been changed since the existing hashfile
    was created, this is a no-op.

    @param hashfile: file to create. If it already exists, it will
                     atomically be updated.

    @param logfile: file to read from. It must exist.

    @param hash_size: Valid values are 0, 4, 8. 0 means autoselect
                      hash size. 4 is 32 bit hash, 8 is 64 bit hash.

    """
    libsparkey.sparkey_hash_write(hashfile, logfile, hash_size)


class HashReader(object):
    """This is a reader that supports both iteration and random lookups."""

    def __init__(self, hashfile, logfile):
        """Opens a hash file and log file for reading.

        @param hashfile: Hash file to open, must exist and be
                         associated with the log file.

        @param logfile: Log file to open, must exist.

        """
        self._reader = ffi.new("struct sparkey_hashreader**")
        rc = libsparkey.sparkey_hash_open(self._reader, hashfile, logfile)
        if rc != 0:
            error_str = ffi.string(libsparkey.sparkey_errstring(rc))
            raise Exception(error_str)
        self._iterator = ffi.new("sparkey_logiter**")
        self._log = libsparkey.sparkey_hash_getreader(self._reader[0])
        libsparkey.sparkey_logiter_create(self._iterator, self._log)

    def __del__(self):
        self.close()

    def close(self):
        """Safely close the reader."""
        if self._reader is not None:
            libsparkey.sparkey_hash_close(self._reader)
            self._reader = None

        if self._iterator is not None:
            libsparkey.sparkey_logiter_close(self._iterator)
            self._iterator = None

    def __iter__(self):
        """Iterate through all live entries."""
        return iterate_items(self)

    def _assert_open(self):
        if self._reader is None:
            raise SparkeyException("HashReader is closed")

    def __getitem__(self, key):
        """reader[key] throws KeyError exception when key doesn't exist,
        otherwise is equivalent to reader.get(key) (see L{get})

        """
        value = self.get(key)
        if value is None:
            raise KeyError(key)
        return value

    def __contains__(self, key):
        self._assert_open()
        iterator_ = self._iterator[0]
        libsparkey.sparkey_hash_get(self._reader[0], key, len(key), iterator_)
        return libsparkey.sparkey_logiter_state(iterator_) == libsparkey.SPARKEY_ITER_ACTIVE

    def has_key(self, key):
        return self.__contains__(key)

    def _value_chunk(self, maxlen):
        iterator_ = self._iterator[0]
        res = ""
        while maxlen > 0:
            buff = ffi.new("uint8_t **")
            blen = ffi.new("uint64_t*")
            libsparkey.sparkey_logiter_valuechunk(iterator_, self._log, maxlen, buff, blen)
            if blen == 0:
                return res
            res += ffi.string(buff[0], blen[0])
            maxlen -= blen[0]
        return res


    def get(self, key):
        """Retrieve the value assosiated with the key

        @param key: must be a string

        @returns: the value associated with the key, or None if the
                  key does not exist.
        """
        iterator_ = self._iterator[0]
        rc = libsparkey.sparkey_hash_get(self._reader[0], key, len(key), iterator_)
        if rc != 0:
            raise SparkeyException(ffi.string(libsparkey.sparkey_errstring(rc)))
        if libsparkey.sparkey_logiter_state(iterator_) != libsparkey.SPARKEY_ITER_ACTIVE:
            return None
        assert libsparkey.sparkey_logiter_type(iterator_) == libsparkey.SPARKEY_ENTRY_PUT
        valuelen = libsparkey.sparkey_logiter_valuelen(iterator_)
        return self._value_chunk(valuelen)

    def __len__(self):
        return libsparkey.sparkey_hash_numentries(self._reader[0])

# helpers
def chunk_with_func(func, maxlen, iterator, log):
    res = ""
    while maxlen > 0:
        buff = ffi.new("uint8_t **")
        blen = ffi.new("uint64_t*")
        func(iterator, log, maxlen, buff, blen)
        if blen == 0:
            return res
        res += ffi.string(buff[0], blen[0])
        maxlen -= blen[0]
    return res


key_chunk = partial(chunk_with_func,
                    libsparkey.sparkey_logiter_keychunk)

value_chunk = partial(chunk_with_func,
                      libsparkey.sparkey_logiter_valuechunk)

#iterator generator
def iterate_items(hash_reader):
    reader = hash_reader._reader
    iterator = ffi.new("sparkey_logiter**")
    log = libsparkey.sparkey_hash_getreader(reader[0])
    libsparkey.sparkey_logiter_create(iterator, log)
    iterator_ = iterator[0]
    while 1:
        libsparkey.sparkey_logiter_hashnext(iterator_, reader[0])
        if libsparkey.sparkey_logiter_state(iterator_) != libsparkey.SPARKEY_ITER_ACTIVE:
            break
        valuelen = libsparkey.sparkey_logiter_valuelen(iterator_)
        keylen = libsparkey.sparkey_logiter_keylen(iterator_)
        key = key_chunk(keylen, iterator_, log)
        value = value_chunk(valuelen, iterator_, log)
        yield key, value
    libsparkey.sparkey_logiter_close(iterator)


class HashWriter(object):
    def __init__(self, hashfile, logfile, mode='NEW',
                 compression_type=Compression.NONE, compression_block_size=0,
                 hash_size=0):
        """Creates a new writer.

        Does everything that L{LogWriter} does, but also writes the
        hash file.

        @param hashfile: filename of hash file

        @param logfile: filename of log file

        @param mode: Same as in L{LogWriter.__init__}

        @param compression_type: Same as in L{LogWriter.__init__}

        @param compression_block_size: Same as in L{LogWriter.__init__}

        @param hash_size: Valid values are 0, 4, 8. 0 means autoselect
                          hash size . 4 is 32 bit hash, 8 is 64 bit hash.

        """
        self._logwriter = LogWriter(logfile, mode, compression_type,
                                    compression_block_size)
        self._hashfile = hashfile
        self._logfile = logfile
        self._reader = None
        self._hash_size = hash_size

    def _assert_open(self):
        if self._logwriter is None:
            raise SparkeyException("Writer is closed")

    def __setitem__(self, key, value):
        """Equivalent to writer.put(key, value), see L{put}"""
        self.put(key, value)

    def put(self, k, v):
        """Append the key-value pair to the log.

        @param key: must be a string

        @param value: must be a string

        """
        self._logwriter.put(k, v)

    def __delitem__(self, key):
        """Equivalent to writer.delete(key), see L{delete}"""
        self.delete(key)

    def delete(self, k):
        """Appends a delete operation of key to the log.

        @param key: must be a string

        """
        self._assert_open()
        self._logwriter.delete(k)

    def flush(self):
        """Flushes all log writes, and also rebuilds the hash."""
        self._assert_open()
        self._logwriter.flush()
        writehash(self._hashfile, self._logfile, self._hash_size)

    def __del__(self):
        self.destroy()

    def destroy(self):
        """Closes the writer, but does not flush anything.

        All writes before the previous flush will be gone.

        """
        if self._logwriter is not None:
            self._logwriter.close()
            self._logwriter = None
        self._close_reader()
        self._hashfile = None
        self._logfile = None

    def finish(self):
        """Equivalent to L{close}"""
        self.close()

    def close(self):
        """Flushes pending log writes from memory to disk, rewrites the hash
        file and closes the writer.

        """
        if self._logwriter is not None:
            self.flush()
            self.destroy()

    # Reader related code
    def _close_reader(self):
        if self._reader is not None:
            self._reader.close()
            self._reader = None

    def _init_reader(self):
        if self._reader is None:
            self._reader = HashReader(self._hashfile, self._logfile)
        return self._reader

    def __iter__(self):
        """Equivalent to L{iteritems}"""
        return self.iteritems()

    def iteritems(self):
        """Iterate through all entries that have been flushed.

        @returns: L{HashIterator}

        """
        self._assert_open()
        return self._init_reader().iteritems()

    def __getitem__(self, key):
        """Equivalent to writer.get(key), see L{get}"""
        self._assert_open()
        return self._init_reader().get(key)

    def get(self, key):
        """Performs a hash lookup of a key.

        Only finds things that were flushed to the hash.

        @param key: must be a string

        @returns: the value associated with the key, or None if the
                  key does not exist in the hash.

        """
        self._assert_open()
        return self._init_reader().get(key)
