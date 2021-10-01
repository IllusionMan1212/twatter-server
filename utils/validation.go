package utils

import (
	"errors"
	"net/http"
	"time"

	"github.com/illusionman1212/twatter-server/models"
	"github.com/illusionman1212/twatter-server/redissession"
)

func ValidateSession(req *http.Request, w http.ResponseWriter) (*models.User, error) {
	session := redissession.GetSession(req)
	if session.IsNew {
		UnauthorizedWithJSON(w, `{
			"message": "Not authorized to perform this action",
			"status": 401,
			"success": false
		}`)
		return &models.User{}, errors.New("Error while checking the user's session, session is new")
	}

	sessionUser, ok := session.Values["user"].(*models.User)
	if !ok {
		UnauthorizedWithJSON(w, `{
			"message": "Unauthorized user, please log in",
			"status": "401",
			"success": false
		}`)
		return &models.User{}, errors.New("Error while extracting user info from session, either invalid session or internal error")
	}

	return sessionUser, nil
}

func isLeapYear(year int) bool {
	if year%400 == 0 {
		return true
	} else if year%100 == 0 {
		return false
	} else if year%4 == 0 {
		return true
	}
	return false
}

func ValidateBirthday(birthday models.Birthday) bool {
	if birthday.Day == 1 && birthday.Month == 1 && birthday.Year == 1 {
		return false
	}

	today := time.Now().UTC()
	currentYear, currentMonth, currentDay := today.Date()

	if birthday.Day < 1 || birthday.Day > 31 || birthday.Month < 1 || birthday.Month > 12 {
		return false
	}

	if birthday.Year < (currentYear - 100) {
		return false
	}

	if birthday.Year == currentYear {
		if birthday.Month > int(currentMonth) {
			return false
		}

		if birthday.Month == int(currentMonth) && birthday.Day >= currentDay {
			return false
		}
	}

	maxDays := 30

	switch birthday.Month {
	case 1:
	case 3:
	case 5:
	case 7:
	case 8:
	case 10:
	case 12:
		maxDays = 31
	case 4:
	case 6:
	case 9:
	case 11:
		maxDays = 30
	case 2:
		if isLeapYear(birthday.Year) {
			maxDays = 29
		} else {
			maxDays = 28
		}
	}

	if birthday.Day > maxDays {
		return false
	}

	return true
}
