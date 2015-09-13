import modules.Tor.cell.cell as cell
import struct
import logging
log = logging.getLogger(__name__)

def parse_cell(in_buffer, _cell=None):
    """
    Parses a cell. Returns the new input buffer, the cell, whether or not the cell
    is completely read and whether it needs more data.
    """
    ready = False

    # If the cell is None, then this is a new cell. Parse the entire header to determine
    # cell type and circuit id.
    if not _cell:
        if cell.proto_version < 4 and len(in_buffer) < 3:
            return in_buffer, _cell, ready, False
        elif cell.proto_version == 4 and len(in_buffer) < 5:
            return in_buffer, _cell, ready, False

        if cell.proto_version < 4:
            header = struct.unpack('>HB', in_buffer[:3])
            in_buffer = in_buffer[3:]
        else:
            header = struct.unpack('>IB', in_buffer[:5])
            in_buffer = in_buffer[5:]

        if header[1] in cell.cell_types:
            _cell = cell.cell_types[header[1]](header[0])
        else:
            log.warning('received unknown cell type: %d.' % header[1])
            raise cell.CellError('Unknown cell type: %d.' % header[1])

        log.debug('received cell header type %s' % cell.cell_type_to_name(header[1]))
    # Parse a fixed cell, just read in 509 bytes.
    elif _cell and _cell.fixed:
        if len(in_buffer) < 509:
            return in_buffer, _cell, ready, False

        _cell.unpack(in_buffer[:509])
        in_buffer = in_buffer[509:]
        ready = True
    # Read length of a variable length cell.
    elif _cell and not _cell.fixed and not _cell.has_len():
        if len(in_buffer) < 2:
            return in_buffer, _cell, ready, False

        _cell.len(in_buffer[:2])
        in_buffer = in_buffer[2:]
    # Parse the variable length cell.
    elif _cell and not _cell.fixed:
        if len(in_buffer) < _cell.len():
            return in_buffer, _cell, ready, False

        _cell.unpack(in_buffer[:_cell.len()])
        in_buffer = in_buffer[_cell.len():]
        ready = True

    return in_buffer, _cell, ready, True
