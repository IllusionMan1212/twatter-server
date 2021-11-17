package sockets

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/illusionman1212/twatter-server/db"
	"github.com/illusionman1212/twatter-server/functions"
	"github.com/illusionman1212/twatter-server/logger"
	"github.com/illusionman1212/twatter-server/models"
	"github.com/illusionman1212/twatter-server/utils"
)

const (
	dateLayout       = "2006-01-02"
	displayNameRegex = "(?i)^[a-z0-9!$%^&*()_+|~=`{}\\[\\]:\";'<>?,.\\/\\\\\\s-]+$"
)

func UpdateProfile(socketPayload *models.SocketPayload, invokingClient *Client) {
	profile := &models.ProfileValues{}

	utils.UnmarshalJSON([]byte(utils.MarshalJSON(socketPayload.Data)), profile)

	if profile.Bio != "" {
		if len(profile.Bio) > 150 {
			payload := `{
				"eventType": "error",
				"data": {
					"message": "Bio cannot be longer than 150 characters"
				}
			}`

			invokingClient.emitEvent([]byte(payload))
			logger.Errorf("Bio with over 150 characters rejected")
			return
		}

		query := `UPDATE users SET bio = $1 WHERE id = $2;`
		_, err := db.DBPool.Exec(context.Background(), query, profile.Bio, invokingClient.userId)

		if err != nil {
			sendGenericSocketErr(invokingClient)
			logger.Errorf("Error while updating user's bio: %v", err)
			return
		}
	}

	regex, err := regexp.Compile(displayNameRegex)
	if err != nil {
		sendGenericSocketErr(invokingClient)
		logger.Errorf("Error while compiling displayname regex: %v", err)
		return
	}

	displayName := strings.TrimSpace(profile.DisplayName)

	if displayName != "" {
		if regex.MatchString(displayName) {
			query := `UPDATE users SET display_name = $1 WHERE id = $2;`
			_, err := db.DBPool.Exec(context.Background(), query, displayName, invokingClient.userId)
			if err != nil {
				sendGenericSocketErr(invokingClient)
				logger.Errorf("Error while updating user's display name: %v", err)
				return

			}
		} else {
			payload := `{
				"eventType": "error",
				"data": {
					"message": "Display name cannot contain special characters"
				}
			}`

			invokingClient.emitEvent([]byte(payload))
			return
		}
	} else {
		payload := `{
			"eventType": "error",
			"data": {
				"message": "Display name cannot be empty"
			}
		}`

		invokingClient.emitEvent([]byte(payload))
		return
	}

	if profile.ProfileImage.Data != "" {
		if !utils.AllowedProfileImageMimetypes[profile.ProfileImage.Mimetype] {
			errPayload := `{
				"eventType": "error",
				"data": {
					"message": "Unsupported file format"
				}
			}`
			invokingClient.emitEvent([]byte(errPayload))
			logger.Error("Unsupported file format")
			return
		}

		buf, err := base64.StdEncoding.DecodeString(profile.ProfileImage.Data)
		if err != nil {
			sendGenericSocketErr(invokingClient)
			logger.Errorf("Error while decoding base64 string: %v", err)
			return
		}

		err = functions.WriteProfileImage(profile.ProfileImage.Mimetype, invokingClient.userId, buf)
		if err != nil {
			sendGenericSocketErr(invokingClient)
			logger.Errorf("Error while writing profile image: %v", err)
			return
		}
	}

	isBirthdayValid := utils.ValidateBirthday(profile.Birthday)

	var birthday time.Time
	var birthdayString string

	if isBirthdayValid && profile.IsBirthdaySet {
		birthday := fmt.Sprintf("%v-%v-%v", profile.Birthday.Year, profile.Birthday.Month, profile.Birthday.Day)

		query := `UPDATE users SET birthday = $1 WHERE id = $2;`
		_, err := db.DBPool.Exec(context.Background(), query, birthday, invokingClient.userId)
		if err != nil {
			sendGenericSocketErr(invokingClient)
			logger.Errorf("Error while updating user's birthday: %v", err)
			return
		}

		day := fmt.Sprintf("%v", profile.Birthday.Day)
		month := fmt.Sprintf("%v", profile.Birthday.Month)
		year := fmt.Sprintf("%v", profile.Birthday.Year)

		if profile.Birthday.Day < 10 {
			day = "0" + day
		}

		if profile.Birthday.Month < 10 {
			month = "0" + month
		}

		birthdayString = year + "-" + month + "-" + day
	} else if !isBirthdayValid && profile.IsBirthdaySet {
		payload := `{
			"eventType": "error",
			"data": {
				"message": "Invalid birthday, please enter a correct one."
			}
		}`

		invokingClient.emitEvent([]byte(payload))
		logger.Errorf("Attempt to change birthday to an invalid one: %v", profile.Birthday)
		return
	} else {
		birthdayString = dateLayout
	}

	birthday, err = time.Parse(dateLayout, birthdayString)
	if err != nil {
		sendGenericSocketErr(invokingClient)
		logger.Errorf("Error while parsing date: %v", err)
		return
	}

	payload := &models.SocketPayload{}
	dataPayload := &models.UpdateProfileReturnPayload{}

	dataPayload.UserID = invokingClient.userId
	dataPayload.DisplayName = displayName
	dataPayload.Bio = profile.Bio
	dataPayload.ProfileImage = profile.ProfileImage.Data
	dataPayload.Birthday.Time = birthday
	dataPayload.Birthday.Valid = isBirthdayValid

	payload.EventType = "updateProfile"
	payload.Data = dataPayload

	invokingClient.emitEvent([]byte(utils.MarshalJSON(payload)))
}

func RemoveBirthday(socketPayload *models.SocketPayload, invokingClient *Client) {
	_, err := db.DBPool.Exec(context.Background(), "UPDATE users SET birthday = null WHERE id = $1;", invokingClient.userId)
	if err != nil {
		sendGenericSocketErr(invokingClient)
		logger.Errorf("Error while removing user's birthday: %v", err)
		return
	}

	payload := &models.SocketPayload{}
	dataPayload := &models.RemoveBirthdayReturnPayload{}

	dataPayload.ID = invokingClient.userId

	payload.EventType = "birthdayRemoved"
	payload.Data = dataPayload

	invokingClient.emitEvent([]byte(utils.MarshalJSON(payload)))
}
