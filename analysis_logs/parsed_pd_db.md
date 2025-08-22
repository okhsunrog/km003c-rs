Time: 6.018000, Vbus: 0.000V, Ibus: 0.000A, Raw (hex): 458217000011
  -> [Conn] Attach: CC1
     [parsed ConnectionEvent] type_id 45 ts_bytes [130, 23, 0] reserved 00 event_data 11
Time: 6.297000, Vbus: 5.084V, Ibus: 0.072A, Raw (hex): 9f9918000000a1612c9101082cd102002cc103002cb10400454106003c21dcc0
  -> [PD ->] SourceCapabilities:
  [1] Fixed:       5.00 V @ 3.00 A
  [2] Fixed:       9.00 V @ 3.00 A
  [3] Fixed:       12.00 V @ 3.00 A
  [4] Fixed:       15.00 V @ 3.00 A
  [5] Fixed:       20.00 V @ 3.25 A
  [6] PPS:         3.30 - 11.00 V @ 3.00 A

     [parsed PdMessage] is_src_to_snk true timestamp 6297 pd_bytes b"\xa1a,\x91\x01\x08,\xd1\x02\0,\xc1\x03\0,\xb1\x04\0EA\x06\0<!\xdc\xc0"
Time: 6.300000, Vbus: 5.084V, Ibus: 0.072A, Raw (hex): 9f9c18000000a1612c9101082cd102002cc103002cb10400454106003c21dcc0
  -> [PD ->] SourceCapabilities:
  [1] Fixed:       5.00 V @ 3.00 A
  [2] Fixed:       9.00 V @ 3.00 A
  [3] Fixed:       12.00 V @ 3.00 A
  [4] Fixed:       15.00 V @ 3.00 A
  [5] Fixed:       20.00 V @ 3.25 A
  [6] PPS:         3.30 - 11.00 V @ 3.00 A

     [parsed PdMessage] is_src_to_snk true timestamp 6300 pd_bytes b"\xa1a,\x91\x01\x08,\xd1\x02\0,\xc1\x03\0,\xb1\x04\0EA\x06\0<!\xdc\xc0"
Time: 6.302000, Vbus: 5.084V, Ibus: 0.072A, Raw (hex): 9f9e18000000a1612c9101082cd102002cc103002cb10400454106003c21dcc0
  -> [PD ->] SourceCapabilities:
  [1] Fixed:       5.00 V @ 3.00 A
  [2] Fixed:       9.00 V @ 3.00 A
  [3] Fixed:       12.00 V @ 3.00 A
  [4] Fixed:       15.00 V @ 3.00 A
  [5] Fixed:       20.00 V @ 3.25 A
  [6] PPS:         3.30 - 11.00 V @ 3.00 A

     [parsed PdMessage] is_src_to_snk true timestamp 6302 pd_bytes b"\xa1a,\x91\x01\x08,\xd1\x02\0,\xc1\x03\0,\xb1\x04\0EA\x06\0<!\xdc\xc0"
Time: 6.448000, Vbus: 5.091V, Ibus: 0.001A, Raw (hex): 9f3019000000a1632c9101082cd102002cc103002cb10400454106003c21dcc0
  -> [PD ->] SourceCapabilities:
  [1] Fixed:       5.00 V @ 3.00 A
  [2] Fixed:       9.00 V @ 3.00 A
  [3] Fixed:       12.00 V @ 3.00 A
  [4] Fixed:       15.00 V @ 3.00 A
  [5] Fixed:       20.00 V @ 3.25 A
  [6] PPS:         3.30 - 11.00 V @ 3.00 A

     [parsed PdMessage] is_src_to_snk true timestamp 6448 pd_bytes b"\xa1c,\x91\x01\x08,\xd1\x02\0,\xc1\x03\0,\xb1\x04\0EA\x06\0<!\xdc\xc0"
Time: 6.448000, Vbus: 5.091V, Ibus: 0.001A, Raw (hex): 8730190000004102
  -> [PD ->] Message { header: Header { 0: 577, extended: false, num_objects: 0, message_id: 1, port_power_role: Sink, spec_revision: Ok(R2_0), port_data_role: Ufp, message_type_raw: 1 }, data: None }
     [parsed PdMessage] is_src_to_snk true timestamp 6448 pd_bytes b"A\x02"
Time: 6.452000, Vbus: 5.091V, Ibus: 0.001A, Raw (hex): 8b34190000008210dc700323
  -> [PD <-] Message { header: Header { 0: 4226, extended: false, num_objects: 1, message_id: 0, port_power_role: Sink, spec_revision: Ok(R3_0), port_data_role: Ufp, message_type_raw: 2 }, data: Some(PowerSourceRequest(Unknown(RawDataObject { 0: 587428060, object_position: 2 }))) }
     [parsed PdMessage] is_src_to_snk false timestamp 6452 pd_bytes b"\x82\x10\xdcp\x03#"
Time: 6.453000, Vbus: 5.091V, Ibus: 0.001A, Raw (hex): 8735190000002101
  -> [PD ->] Message { header: Header { 0: 289, extended: false, num_objects: 0, message_id: 0, port_power_role: Source, spec_revision: Ok(R1_0), port_data_role: Dfp, message_type_raw: 1 }, data: None }
     [parsed PdMessage] is_src_to_snk true timestamp 6453 pd_bytes b"!\x01"
Time: 6.457000, Vbus: 5.091V, Ibus: 0.001A, Raw (hex): 873919000000a305
  -> [PD ->] Message { header: Header { 0: 1443, extended: false, num_objects: 0, message_id: 2, port_power_role: Source, spec_revision: Ok(R3_0), port_data_role: Dfp, message_type_raw: 3 }, data: None }
     [parsed PdMessage] is_src_to_snk true timestamp 6457 pd_bytes b"\xa3\x05"
Time: 6.457000, Vbus: 5.091V, Ibus: 0.001A, Raw (hex): 8739190000004104
  -> [PD ->] Message { header: Header { 0: 1089, extended: false, num_objects: 0, message_id: 2, port_power_role: Sink, spec_revision: Ok(R2_0), port_data_role: Ufp, message_type_raw: 1 }, data: None }
     [parsed PdMessage] is_src_to_snk true timestamp 6457 pd_bytes b"A\x04"
Time: 6.589000, Vbus: 9.086V, Ibus: 0.012A, Raw (hex): 87bd19000000a607
  -> [PD ->] Message { header: Header { 0: 1958, extended: false, num_objects: 0, message_id: 3, port_power_role: Source, spec_revision: Ok(R3_0), port_data_role: Dfp, message_type_raw: 6 }, data: None }
     [parsed PdMessage] is_src_to_snk true timestamp 6589 pd_bytes b"\xa6\x07"
Time: 6.590000, Vbus: 9.086V, Ibus: 0.012A, Raw (hex): 87be190000004106
  -> [PD ->] Message { header: Header { 0: 1601, extended: false, num_objects: 0, message_id: 3, port_power_role: Sink, spec_revision: Ok(R2_0), port_data_role: Ufp, message_type_raw: 1 }, data: None }
     [parsed PdMessage] is_src_to_snk true timestamp 6590 pd_bytes b"A\x06"
Time: 8.860000, Vbus: 5.114V, Ibus: 0.000A, Raw (hex): 459c22000012
  -> [Conn] Detach: CC1
     [parsed ConnectionEvent] type_id 45 ts_bytes [156, 34, 0] reserved 00 event_data 12
