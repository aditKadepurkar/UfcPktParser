# High Level Analyzer for The University of Minnesota Rocketry Team's UFC(Universal Flight Computer)

# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
import struct

'''
Default values for delims and statuses
Will be able to be changed for an instance in settings, 
but these will always be the global defaults unless I am
told I need to change them.
'''
HDR_DELIM = 0xCA11AB1E
FTR_DELIM = 0xba5eba11
STATUS_DELIM = 0x33
STATUS_NOT_NOACT = 0b11
STATUS_TX = 0b10
STATUS_RX = 0b01
STATUS_BAD = 0x70


### Dictionaries that contain the various settings that can be configured for this plugin.

''' Display formats to choose between '''
DISPLAY_FORMAT_CHOICES = {
    'Hex': 'Hex',
    'Binary': 'Binary'
}

''' Source choices:
    Peripheral - Will use miso data
    Host - Will use mosi data '''
SRC_CHOICES = {
    'Peripheral': 'Peripheral',
    'Host': 'Host'
}

''' The possible modes to configure this analyzer to.
    Status - shows the HDR, FTR, and different statuses in the data( !!! Most people should use this !!! )
    Packet - shows the packet as a whole without breaking down the data inside '''
MODE_CHOICES = {
    'Status': 'Status',
    'Packet': 'Packet'
}

''' The different states that can be given to statuses '''
STATES = ['HDR_STATE', 'DATA_STATE', 'FTR_STATE', 'NO_STATE', 'BAD_STATUS']



# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    '''List of settings that a user can set for this High Level Analyzer.'''
    # hdr_delim_setting = StringSetting()
    # ftr_delim_setting = StringSetting()
    # sts_delim_setting = StringSetting()
    src_choice_setting = ChoicesSetting(label='Source Choice', choices=SRC_CHOICES.keys())
    mode_choice_setting = ChoicesSetting(label = 'Mode', choices = MODE_CHOICES.keys())


    # Output types
    result_types = {
        'dec': {
            'format': '{{data.prefix}}'
        }
    }

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''
        self.sts_delim = struct.pack('H', STATUS_DELIM)[0:1]
        self.hdr_delim = struct.pack('>I', HDR_DELIM)
        self.ftr_delim = struct.pack('>I', FTR_DELIM)
        self.sts_not_noact = struct.pack('b', STATUS_NOT_NOACT)[0]
        self.sts_tx = struct.pack('b', STATUS_TX)[0]
        self.sts_rx = struct.pack('b', STATUS_RX)[0]
        self.sts_bad = struct.pack('b', STATUS_BAD)[0]
        self.last_frame = [None, '']
        self.packet_start = None

        print("Status Delimiter: 0x", self.sts_delim.hex())
        print("Footer Delimiter: 0x", self.ftr_delim.hex())
        print("Header Delimiter: 0x", self.hdr_delim.hex())

        self.set_NOSTATE()


    """
    Functions that set the states of frames
    """
    def set_NOSTATE(self):
        self.curr_state = STATES[3]

    def set_HDRSTATE(self):
        self.curr_state = STATES[0]

    def set_FTRSTATE(self):
        self.curr_state = STATES[2]

    def set_DATASTATE(self):
        self.curr_state = STATES[1]
    
    def set_BADSTATE(self):
        self.curr_state = STATES[4]


    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''

        # For pkt hdrs and ftrs - this basically just makes sure the compiler doesn't get mad on possible edge cases
        if (self.last_frame[0] == None):
            self.last_frame[0] = frame

        # We only want frames of type result
        if (frame.type != 'result'):
            self.set_NOSTATE()
            return

        # Choose data based on settings
        data = frame.data['miso']
        if self.src_choice_setting == "Host":
            data = frame.data['mosi']

        # This is basically what we will use for returning statuses and HDR/FTR tags
        decode_val = ""

        # Looking to see if there is a FTR
        if self.last_frame[1] == 'H':
            if data[0:2] == self.hdr_delim[0:2]:
                decode_val = "Header"
                self.set_HDRSTATE()
                labeled = True
                # grabbing start time so we can reset last_frame before return
                start_time = self.last_frame[0].start_time
                self.last_frame = [frame, '']
                # checks settings to decide what needs to be returned
                if (self.mode_choice_setting == 'Packet'):
                    self.packet_start = start_time
                    return
                return AnalyzerFrame( 'dec', start_time, frame.end_time, {
                    'prefix':decode_val #, 'decoded': char.strip() 
                })

        # Looking to see if there is a FTR
        if self.last_frame[1] == 'T':
            if data[0:2] == self.ftr_delim[0:2]:
                decode_val = "Footer"
                labeled = True
                self.set_FTRSTATE()
                # grabbing start time so we can reset last_frame before return
                start_time = self.last_frame[0].start_time
                self.last_frame = [frame, '']
                # checks settings to decide what needs to be returned
                if (self.mode_choice_setting == 'Packet'):
                    # This should never evaluate to false, but good to have
                    if (self.packet_start != None):
                        packet_start = self.packet_start
                        return AnalyzerFrame( 'dec', packet_start, frame.end_time, {
                            'prefix':"Packet"
                            })
                    else:
                        return
                else:
                    return AnalyzerFrame( 'dec', start_time, frame.end_time, {
                        'prefix':decode_val #, 'decoded': char.strip() 
                    })



        if data[0:2] == self.hdr_delim[2:4]:
            self.last_frame = [frame, 'H']
            # self.start_pkt_frame()
        elif data[0:2] == self.ftr_delim[2:4]:
            self.last_frame = [frame,'T']
        elif data[0:1] == self.sts_delim:
            # Doesn't need to keep going if the mode is Packet
            if (self.mode_choice_setting == 'Packet'):
                return
            decode_val = "Status"
            self.set_NOSTATE()
            labeled = False
            if data[1] & self.sts_tx:
                decode_val = decode_val + " (TX)"
                labeled = True
            elif data[1] & self.sts_rx:
                decode_val = decode_val + " (RX)"
                labeled = True
            elif data[1] & self.sts_bad:
                decode_val = decode_val + " (Bad Status)"
                labeled = True
            elif not(data[1] & self.sts_not_noact):
                decode_val = decode_val + " (NoAct)"
                labeled = True
            elif not labeled:
                decode_val = decode_val + " (Unknown!)"
                labeled = True

        # No status delim found/ HDR or FTR first pass
        if decode_val == "":
            return

        return AnalyzerFrame( 'dec', frame.start_time, frame.end_time, {
            'prefix':decode_val #, 'decoded': char.strip() 
        })
