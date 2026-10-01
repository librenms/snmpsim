#
# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#
# Simulation data file management tools
#
import collections
import functools
import os
import stat

from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.carrier.asyncio.dgram import udp6
from pysnmp.proto import rfc1902
from pysnmp.smi import exval
from pysnmp.smi.error import MibOperationError

from snmpsim import confdir
from snmpsim import fastber
from snmpsim import log
from snmpsim import utils
from snmpsim import variation
from snmpsim.error import NoDataNotification
from snmpsim.error import SnmpsimError
from snmpsim.record.search.database import RecordIndex
from snmpsim.record.search.file import get_record
from snmpsim.record.search.file import search_record_by_oid
from snmpsim.reporting.manager import ReportingManager

SELF_LABEL = "self"


class AbstractLayout:
    layout = "?"


class DataFile(AbstractLayout):
    layout = "text"
    # open data files, least recently used first, with their index sizes
    opened_queue = collections.OrderedDict()
    opened_index_size = 0
    max_queue_entries = 256  # max number of open text files
    # loaded indices take about five times their on-disk size in memory
    max_queue_index_size = 32 * 1024 * 1024  # bytes of on-disk index

    def __init__(self, textFile, textParser, variationModules, preEncode=False):
        self._record_index = RecordIndex(textFile, textParser)
        self._text_parser = textParser
        self._text_file = textFile
        self._variation_modules = variationModules
        # respond with fastber.EncodedVarBind for plain snmprec records
        self._pre_encode = preEncode and isinstance(
            textParser, variation.SnmprecRecordMixIn
        )

    def index_text(self, forceIndexBuild=False, validateData=False):
        self._record_index.create(forceIndexBuild, validateData)
        return self

    def close(self):
        size = DataFile.opened_queue.pop(self, None)

        if size is not None:
            DataFile.opened_index_size -= size

        if self._record_index.is_open():
            self._record_index.close()

    def get_handles(self):
        queue = DataFile.opened_queue

        if not self._record_index.is_open():
            log.info("Opening %s" % self)

        # may also reopen the data file if it has been modified
        handles = self._record_index.get_handles()

        size = self._record_index.index_size()

        DataFile.opened_index_size += size - queue.pop(self, 0)
        queue[self] = size

        # the most recently used data file stays open regardless
        while len(queue) > 1 and (
            len(queue) > self.max_queue_entries
            or DataFile.opened_index_size > self.max_queue_index_size
        ):
            data_file = next(iter(queue))
            log.info("Closing %s" % data_file)
            data_file.close()

        return handles

    def process_var_binds(self, var_binds, **context):
        rsp_var_binds = []

        if context.get("nextFlag"):
            error_status = exval.endOfMib

        else:
            error_status = exval.noSuchInstance

        try:
            text, db = self.get_handles()

        except SnmpsimError as exc:
            log.error("Problem with data file or its index: %s" % exc)

            ReportingManager.update_metrics(
                data_file=self._text_file,
                datafile_failure_count=1,
                transport_call_count=1,
                **context,
            )

            return [(vb[0], error_status) for vb in var_binds]

        vars_remaining = vars_total = len(var_binds)
        err_total = 0

        if log.enabled(log.LOG_INFO):
            log.info(
                "Request var-binds: %s, flags: %s, "
                "%s"
                % (
                    ", ".join([f"{vb[0]}=<{vb[1].prettyPrint()}>" for vb in var_binds]),
                    context.get("nextFlag") and "NEXT" or "EXACT",
                    context.get("setFlag") and "SET" or "GET",
                )
            )

        pre_encode = self._pre_encode and not context.get("setFlag")

        for var_bind in var_binds:
            if type(var_bind) is fastber.EncodedVarBind:
                # spare building pyasn1 objects unless needed below
                text_oid = var_bind.key
                oid = val = None

            else:
                oid, val = var_bind
                text_oid = ".".join(map(str, oid))

            try:
                offset, subtree_flag, prev_offset = self._record_index.lookup(text_oid)
                exact_match = True

            except KeyError:
                if oid is None:
                    oid, val = var_bind

                offset = self._record_index.search(oid)

                if offset is None:
                    offset = search_record_by_oid(oid, text, self._text_parser)

                subtree_flag = exact_match = False

            text.seek(offset)

            vars_remaining -= 1

            line, _, _ = get_record(text)  # matched line

            while True:
                if exact_match:
                    if context.get("nextFlag") and not subtree_flag:
                        _next_line, _, _ = get_record(text)  # next line

                        if _next_line:
                            # index keys are OIDs as the grammar parses them
                            _next_oid = self._text_parser.grammar.parse(_next_line)[0]

                            try:
                                _, subtree_flag, _ = self._record_index.lookup(
                                    _next_oid
                                )

                            except KeyError:
                                log.error(
                                    "data error for %s at %s, index "
                                    "broken?" % (self, _next_oid)
                                )
                                line = ""  # fatal error

                            else:
                                line = _next_line

                        else:
                            line = _next_line

                else:  # search function above always rounds up to the next OID
                    if line:
                        _oid, _ = self._text_parser.evaluate(line, oidOnly=True)

                    else:  # eom
                        _oid = "last"

                    try:
                        _, _, _prev_offset = self._record_index.lookup(str(_oid))

                    except KeyError:
                        log.error(
                            "data error for %s at %s, index " "broken?" % (self, _oid)
                        )
                        line = ""  # fatal error

                    else:
                        # previous line serves a subtree?
                        if _prev_offset >= 0:
                            text.seek(_prev_offset)
                            _prev_line, _, _ = get_record(text)
                            _prev_oid, _ = self._text_parser.evaluate(
                                _prev_line, oidOnly=True
                            )

                            if _prev_oid.isPrefixOf(oid):
                                # use previous line to the matched one
                                line = _prev_line
                                subtree_flag = True

                if pre_encode and line and (exact_match or context.get("nextFlag")):
                    _var_bind = self._encode_plain(line)

                    if _var_bind:
                        break

                if oid is None:
                    oid, val = var_bind

                if not line:
                    _var_bind = oid, error_status
                    break

                call_context = context.copy()
                call_context.update(
                    (),
                    origOid=oid,
                    origValue=val,
                    dataFile=self._text_file,
                    subtreeFlag=subtree_flag,
                    exactMatch=exact_match,
                    errorStatus=error_status,
                    varsTotal=vars_total,
                    varsRemaining=vars_remaining,
                    variationModules=self._variation_modules,
                )

                try:
                    _var_bind = self._text_parser.evaluate(line, **call_context)

                    if _var_bind[1] is exval.endOfMib:
                        exact_match = True
                        subtree_flag = False
                        continue

                except NoDataNotification:
                    raise

                except MibOperationError:
                    raise

                except Exception as exc:
                    _var_bind = oid, error_status
                    err_total += 1
                    log.error(f"data error at {self} for {text_oid}: {exc}")

                break

            rsp_var_binds.append(_var_bind)

        if log.enabled(log.LOG_INFO):
            log.info(
                "Response var-binds: %s"
                % (
                    ", ".join(
                        [f"{vb[0]}=<{vb[1].prettyPrint()}>" for vb in rsp_var_binds]
                    )
                )
            )

        ReportingManager.update_metrics(
            data_file=self._text_file,
            varbind_count=vars_total,
            datafile_call_count=1,
            datafile_failure_count=err_total,
            transport_call_count=1,
            **context,
        )

        return rsp_var_binds

    def _encode_plain(self, line, fields=None):
        """Pre-encoded var-bind for a plain snmprec record or None"""
        key, tag, value = fields or self._text_parser.grammar.parse(line)

        encoded = fastber.encode_record(key, tag, value)

        if encoded is not None:
            return fastber.EncodedVarBind(
                key,
                encoded,
                functools.partial(
                    self._text_parser.evaluate,
                    line,
                    nextFlag=True,
                    exactMatch=True,
                    setFlag=False,
                ),
            )

    def _read_next_plain(self, text, var_bind, context):
        """GETNEXT for `var_bind` by reading the following record directly.

        Only handles OIDs matching a plain record followed by another
        plain record, returns None otherwise.
        """
        if type(var_bind) is fastber.EncodedVarBind:
            key = var_bind.key

        else:
            key = ".".join(map(str, var_bind[0]))

        entry = self._record_index.get(key)

        if entry is None or entry[1]:  # not found or serving a subtree
            return

        text.seek(entry[0])
        get_record(text)  # matched record

        line, _, _ = get_record(text)

        if not line:
            # end of data, as process_var_binds() responds
            return var_bind[0], exval.endOfMib

        fields = self._text_parser.grammar.parse(line)
        key, tag, _ = fields

        if ":" in tag:  # variation module or subtree
            return

        entry = self._record_index.get(key)

        if entry is None or entry[1]:
            return

        if self._pre_encode:
            # None for unusual records, process_var_binds() handles these
            return self._encode_plain(line, fields)

        oid, val = var_bind

        call_context = context.copy()
        call_context.update(
            (),
            origOid=oid,
            origValue=val,
            dataFile=self._text_file,
            subtreeFlag=False,
            exactMatch=True,
            errorStatus=exval.endOfMib,
            varsTotal=1,
            varsRemaining=0,
            variationModules=self._variation_modules,
        )

        try:
            return self._text_parser.evaluate(line, **call_context)

        except Exception:
            return  # let process_var_binds() handle and report it

    def read_next_run(self, oid, val, count, **context):
        """Results of `count` chained GETNEXT requests starting at `oid`.

        Same as calling process_var_binds() with each previous result,
        but consecutive plain records are read directly from the data file.
        """
        if log.enabled(log.LOG_INFO):
            # keep logging every step
            run = []

            for _ in range(count):
                run.extend(self.process_var_binds([(oid, val)], **context))
                oid, val = run[-1]

            return run

        try:
            text, _ = self.get_handles()

        except SnmpsimError:
            text = None

        run = []
        var_bind = oid, val
        plain_count = 0

        for _ in range(count):
            next_var_bind = text and self._read_next_plain(text, var_bind, context)

            if next_var_bind:
                plain_count += 1

            else:
                (next_var_bind,) = self.process_var_binds([var_bind], **context)

                # the data file may have been reopened
                try:
                    text, _ = self.get_handles()

                except SnmpsimError:
                    text = None

            run.append(next_var_bind)
            var_bind = next_var_bind

        if plain_count:
            ReportingManager.update_metrics(
                data_file=self._text_file,
                varbind_count=plain_count,
                datafile_call_count=plain_count,
                datafile_failure_count=0,
                transport_call_count=plain_count,
                **context,
            )

        return run

    def __str__(self):
        return "%s controller" % self._text_file


def _available_cpus():
    return utils.available_cpus()


def _build_index(text_file, record_type, cache_dir, validate_data):
    """Worker process entry point, may not share any state with the parent"""
    confdir.cache = cache_dir

    RecordIndex(text_file, variation.RECORD_TYPES[record_type])._build(validate_data)


def build_indices(data_files, force_index_build=False, validate_data=False):
    """Build missing or outdated data file indices in parallel.

    Takes (path, record type, community) items as returned by
    get_data_files(). Returns the paths of the data files indexed here,
    other data files are left for DataFile.index_text() to handle.
    """
    record_types = {id(v): k for k, v in variation.RECORD_TYPES.items()}

    pending = {}

    for text_file, text_parser, _ in data_files:
        if text_file in pending or id(text_parser) not in record_types:
            continue

        if RecordIndex(text_file, text_parser).index_needed(force_index_build):
            pending[text_file] = record_types[id(text_parser)]

    workers = min(len(pending), _available_cpus())

    if workers < 2:
        return set()

    log.info("Building %d indices using %d processes" % (len(pending), workers))

    # not needed for a warm start, spare the import time
    from concurrent.futures import ProcessPoolExecutor

    with ProcessPoolExecutor(workers) as executor:
        # results in submission order, so the first broken data file is reported
        for _ in executor.map(
            _build_index,
            pending,
            pending.values(),
            [confdir.cache] * len(pending),
            [validate_data] * len(pending),
            chunksize=8,
        ):
            pass

    return set(pending)


def get_data_files(tgt_dir, top_len=None):
    # If top_len is not provided, calculate it based on the target directory
    if top_len is None:
        top_len = len(tgt_dir.rstrip(os.path.sep).split(os.path.sep))

    # Start processing the directory
    return process_directory(tgt_dir, top_len)


def process_directory(tgt_dir, top_len):
    # Initialize an empty list to store directory content
    dir_content = []
    # Iterate over each file in the target directory
    for d_file in os.listdir(tgt_dir):
        # Get the full path of the file
        full_path = os.path.join(tgt_dir, d_file)
        # Get the inode information of the file
        inode = os.lstat(full_path)
        # If the file is a symbolic link, process it
        if stat.S_ISLNK(inode.st_mode):
            full_path, inode = process_symlink(full_path, tgt_dir)
        # Calculate the relative path of the file
        rel_path = full_path.split(os.path.sep)[top_len:]
        # If the file is a directory, recursively process it
        if stat.S_ISDIR(inode.st_mode):
            dir_content += get_data_files(full_path, top_len)
        # If the file is a regular file, process it
        elif stat.S_ISREG(inode.st_mode):
            dir_content += process_file(d_file, full_path, rel_path)
    # Return the directory content
    return dir_content


def process_symlink(full_path, tgt_dir):
    # Read the target of the symbolic link
    full_path = os.readlink(full_path)
    # If the target is not an absolute path, prepend the target directory
    if not os.path.isabs(full_path):
        full_path = os.path.join(tgt_dir, full_path)
    # Get the inode information of the target file
    inode = os.stat(full_path)
    # Return the full path and inode
    return full_path, inode


def process_file(d_file, full_path, rel_path):
    # Check if the file extension matches any of the record types
    for dExt in variation.RECORD_TYPES:
        if d_file.endswith(dExt):
            # If it does, process the file extension
            return process_file_extension(d_file, full_path, rel_path, dExt)
    # If it does not, return an empty list
    return []


def process_file_extension(d_file, full_path, rel_path, dExt):
    # Process the relative path to create an identifier for the file
    if rel_path[0] == SELF_LABEL:
        rel_path = rel_path[1:]
    if len(rel_path) == 1 and rel_path[0] == SELF_LABEL + os.path.extsep + dExt:
        rel_path[0] = rel_path[0][4:]
    # Join the elements of the relative path to create the identifier
    ident = os.path.join(*rel_path)
    # Remove the file extension from the identifier
    ident = ident[: -len(dExt) - 1]
    # Replace any path separators in the identifier with a forward slash
    ident = ident.replace(os.path.sep, "/")
    # Return a tuple containing the full path, the record type, and the identifier
    return [(full_path, variation.RECORD_TYPES[dExt], ident)]


def probe_context(transport_domain, transport_address, context_engine_id, context_name):
    """Suggest variations of context name based on request data"""
    if context_engine_id:
        candidate = [
            context_engine_id,
            context_name,
            ".".join([str(x) for x in transport_domain]),
        ]

    else:
        # try legacy layout w/o contextEngineId in the path
        candidate = [context_name, ".".join([str(x) for x in transport_domain])]

    if transport_domain[: len(udp.DOMAIN_NAME)] == udp.DOMAIN_NAME:
        candidate.append(transport_address[0])

    elif udp6 and transport_domain[: len(udp6.DOMAIN_NAME)] == udp6.DOMAIN_NAME:
        candidate.append(str(transport_address[0]).replace(":", "_"))

    candidate = [str(x) for x in candidate if x]

    while candidate:
        yield rfc1902.OctetString(
            os.path.normpath(os.path.sep.join(candidate)).replace(os.path.sep, "/")
        ).asOctets()
        del candidate[-1]

    # try legacy layout w/o contextEngineId in the path
    if context_engine_id:
        for candidate in probe_context(
            transport_domain, transport_address, None, context_name
        ):
            yield candidate
