# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
import struct


# HDR_DELIM = 0xCA11AB1E

# We have to
HDR_DELIM = 0xCA11
# FTR_DELIM = 0xba5eba11
FTR_DELIM = 0xBA11
STATUS_DELIM = 0x33
STATUS_NOT_NOACT = 0b11
STATUS_TX = 0b10
STATUS_RX = 0b01
STATUS_BAD = 0x70


DISPLAY_FORMAT_CHOICES = {
    'Hex': 'Hex',
    'Binary': 'Binary'
}
SRC_CHOICES = {
    'Peripheral': 'Peripheral',
    'Host': 'Host'
}

STATES = ['HDR_STATE', 'DATA_STATE', 'FTR_STATE', 'NO_STATE', 'BAD_STATUS']



# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    # hdr_delim_setting = StringSetting()
    # ftr_delim_setting = StringSetting()
    # sts_delim_setting = StringSetting()
    window_length_setting = NumberSetting(label='Width', min_value = 0, max_value = 100)
    src_choice_setting = ChoicesSetting(label='Source Choice', choices=SRC_CHOICES.keys())



    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    # result_types = {
    #     'mytype': {
    #         'format': 'Output type: {{type}}, Input type: {{data.input_type}}'
    #     }
    # }

    result_types = {
        'dec': {
            'format': '{{data.prefix}}'
        },
    }

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''
        self.sts_delim = struct.pack('H', STATUS_DELIM)[0:1]
        self.hdr_delim = struct.pack('>I', HDR_DELIM)[2:4]
        self.ftr_delim = struct.pack('>I', FTR_DELIM)[2:4]
        self.sts_not_noact = struct.pack('b', STATUS_NOT_NOACT)[0]
        self.sts_tx = struct.pack('b', STATUS_TX)[0]
        self.sts_rx = struct.pack('b', STATUS_RX)[0]
        self.sts_bad = struct.pack('b', STATUS_BAD)[0]

        print("Status Delimiter: 0x", self.sts_delim.hex())
        print("Footer Delimiter: 0x", self.ftr_delim.hex())
        print("Header Delimiter: 0x", self.hdr_delim.hex())

        self.set_NOSTATE()

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

    def end_frame(self):
        pass


    def decode(self, frame: AnalyzerFrame):
        # print("Settings:", hex(self.hdr_delim),hex(self.ftr_delim), hex(self.sts_delim))
        # print("Sanity:", hex(self.hdr_delim),hex(self.ftr_delim), hex(self.sts_delim))

        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''

        if (frame.type != 'result'):
            self.set_NOSTATE()
            return


        data = frame.data['miso']
        if self.src_choice_setting == "Host":
            data = frame.data['mosi']

        len(data)
        decode_val = ""
        if data[0:2] == self.hdr_delim:
            decode_val = "Header"
            labeled = True
            # self.end_frame()
            self.set_HDRSTATE()
            # self.start_pkt_frame()
        elif data[0:2] == self.ftr_delim:
            decode_val = "Footer"
            labeled = True
            self.set_FTRSTATE()
            self.end_frame()
        elif data[0:1] == self.sts_delim:
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

        # Return the data frame itself
        # return AnalyzerFrame('mytype', frame.start_time, frame.end_time, {
        #     'input_type': frame.type
        # })

        if decode_val == "":
            return

        return AnalyzerFrame( 'dec', frame.start_time, frame.end_time, {
            'prefix':decode_val #, 'decoded': char.strip() 
        })

        # return AnalyzerFrame( 'prefix':str(self.prefix)})
