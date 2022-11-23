package main

type Message struct { /* value object */
  SenderIndex int
  ProtocolCode protocol_code //TODO design: type is defined in a higher layer
  RecipientIndex int
  RunId string
  Op int
  DTO any
}
