package main

type deliveryMethodEmail struct {}

func (method *deliveryMethodEmail) Send(rv *requestVariables, recipient string, message string) (id string, err error) {
	return id, err
}

func (method *deliveryMethodEmail) Status(rv *requestVariables, id string) (status SenderStatus) {
	return status
}

func init() {
	//RegisterSender("email", &deliveryMethodEmail{})
}
