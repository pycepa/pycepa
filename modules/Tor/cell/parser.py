import modules.Tor.cell.cell as cell
import struct
import logging
log = logging.getLogger(__name__)

def parse_cell(in_buffer, _cell=None):
    ready = False

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

        log.info('received cell header type %s' % cell.cell_type_to_name(header[1]))
    elif _cell and _cell.fixed:
        if len(in_buffer) < 509:
            return in_buffer, _cell, ready, False

        _cell.unpack(in_buffer[:509])
        in_buffer = in_buffer[509:]
        ready = True
    elif _cell and not _cell.fixed and not _cell.has_len():
        if len(in_buffer) < 2:
            return in_buffer, _cell, ready, False

        _cell.len(in_buffer[:2])
        in_buffer = in_buffer[2:]
    elif _cell and not _cell.fixed:
        if len(in_buffer) < _cell.len():
            return in_buffer, _cell, ready, False

        _cell.unpack(in_buffer[:_cell.len()])
        in_buffer = in_buffer[_cell.len():]
        ready = True

    return in_buffer, _cell, ready, True
