package main

type Message struct { /* value object */
  ProtocolCode protocol_code
  RecipientIndex int
  RunId string
  Op int
  DTO any
}
