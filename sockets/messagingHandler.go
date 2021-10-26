package sockets

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/illusionman1212/twatter-server/db"
	"github.com/illusionman1212/twatter-server/logger"
	"github.com/illusionman1212/twatter-server/models"
	"github.com/illusionman1212/twatter-server/utils"
)

func Message(socketPayload *models.SocketPayload, clients []*Client, invokingClient *Client) {
	message := &models.SocketMessage{}

	utils.UnmarshalJSON([]byte(utils.MarshalJSON(socketPayload.Data)), message)

	if invokingClient.userId != message.SenderId {
		errPayload := `{
			"eventType": "error",
			"data": {
				"message": "Unauthorized to perform this action"
			}
		}`
		invokingClient.emitEvent([]byte(errPayload))
		logger.Error("Attempt to send a message with mismatched user ids")
		return
	}

	insertMessageQuery := `INSERT INTO messages(id, author_id, conversation_id, content, read_by)
		VALUES($1, $2, $3, $4, $5)`

	conversationId, err := strconv.Atoi(message.ConversationId)
	if err != nil {
		sendGenericSocketErr(invokingClient)
		logger.Errorf("Error while parsing conversation id: %v", err)
		return
	}

	// TODO: check if conversation exists before writing the message to the DB

	messageId, err := db.Snowflake.NextID()
	if err != nil {
		sendGenericSocketErr(invokingClient)
		logger.Errorf("Error while generating id for new message: %v", err)
		return
	}

	senderId, err := strconv.Atoi(message.SenderId)
	if err != nil {
		sendGenericSocketErr(invokingClient)
		logger.Errorf("Error while converting string to int: %v", err)
		return
	}

	receiverId, err := strconv.Atoi(message.ReceiverId)
	if err != nil {
		sendGenericSocketErr(invokingClient)
		logger.Errorf("Error while converting string to int: %v", err)
		return
	}

	_, err = db.DBPool.Exec(context.Background(), insertMessageQuery, messageId, message.SenderId, conversationId, message.Content, []uint64{uint64(senderId)})
	if err != nil {
		sendGenericSocketErr(invokingClient)
		logger.Errorf("Error while inserting new message into database: %v", err)
		return
	}

	updateQuery := `UPDATE conversations SET last_updated = now() at time zone 'utc', participants = $1 WHERE id = $2`

	participants := []uint64{uint64(senderId), uint64(receiverId)}

	_, err = db.DBPool.Exec(context.Background(), updateQuery, participants, conversationId)
	if err != nil {
		sendGenericSocketErr(invokingClient)
		logger.Errorf("Error while updating conversation's last_updated field: %v", err)
		return
	}

	returnedAttachment, err := writeMessageAttachmentFile(message.Attachment, messageId, message.ConversationId)

	messagePayload := &models.MessageReturnPayload{}
	payload := &models.SocketPayload{}

	messagePayload.MessageID = fmt.Sprintf("%v", messageId)
	messagePayload.Attachment = returnedAttachment
	messagePayload.Content = message.Content
	messagePayload.ConversationID = message.ConversationId
	messagePayload.ReceiverID = message.ReceiverId
	messagePayload.AuthorID = message.SenderId
	messagePayload.SentTime = time.Now().UTC().Format(time.RFC3339)
	messagePayload.Deleted = false

	payload.EventType = "message"
	payload.Data = messagePayload

	for _, receiverClient := range invokingClient.hub.users[fmt.Sprintf("%v", message.ReceiverId)] {
		receiverClient.emitEvent([]byte(utils.MarshalJSON(payload)))
	}

	for _, client := range clients {
		client.emitEvent([]byte(utils.MarshalJSON(payload)))
	}
}

func DeleteMessage(socketPayload *models.SocketPayload, clients []*Client, invokingClient *Client, message []byte) {
	payload := &models.DeleteMessageSocketPayload{}

	utils.UnmarshalJSON([]byte(utils.MarshalJSON(socketPayload.Data)), payload)

	for _, client := range clients {
		client.emitEvent(message)
	}

	for _, client := range invokingClient.hub.users[payload.ReceiverID] {
		client.emitEvent(message)
	}
}

func Typing(socketPayload *models.SocketPayload, invokingClient *Client, eventType string) {
	data := &models.TypingData{}

	utils.UnmarshalJSON([]byte(utils.MarshalJSON(socketPayload.Data)), data)

	// TODO: check if sender id and receiver id are both members of the conversation

	payload := &models.SocketPayload{}
	typingData := &models.TypingReturnPayload{}

	typingData.ConversationID = data.ConversationID

	payload.EventType = eventType
	payload.Data = typingData

	for _, receiverClient := range invokingClient.hub.users[data.ReceiverID] {
		receiverClient.emitEvent([]byte(utils.MarshalJSON(payload)))
	}
}

func MarkMessagesAsRead(socketPayload *models.SocketPayload, invokingClient *Client, clients []*Client) {
	data := &models.MarkMessagesAsReadData{}

	utils.UnmarshalJSON([]byte(utils.MarshalJSON(socketPayload.Data)), data)

	if invokingClient.userId != data.UserID {
		errPayload := `{
			"eventType": "error",
			"data": {
				"message": "Unauthorized to perform this action"
			}
		}`
		invokingClient.emitEvent([]byte(errPayload))
		logger.Error("Attempt to mark messages as read with a mismatched user id")
		return
	}

	updateQuery := `UPDATE messages SET read_by = ARRAY_APPEND(read_by, $1) WHERE conversation_id = $2 AND $1 <> ALL(read_by)`

	_, err := db.DBPool.Exec(context.Background(), updateQuery, invokingClient.userId, data.ConversationID)
	if err != nil {
		sendGenericSocketErr(invokingClient)
	}

	payload := &models.SocketPayload{}
	returnData := &models.MarkMessagesAsReadReturnData{}

	returnData.ConversationID = data.ConversationID

	payload.EventType = "markedMessagesAsRead"
	payload.Data = returnData

	for _, client := range clients {
		client.emitEvent([]byte(utils.MarshalJSON(payload)))
	}
}
