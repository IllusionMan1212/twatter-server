package routes

import "github.com/gorilla/mux"

func RegisterUsersRoutes(router *mux.Router) {
	userRouter := router.PathPrefix("/users").Subrouter()

	userRouter.HandleFunc("/validateToken", ValidateToken).Methods("GET")
	userRouter.HandleFunc("/getUserData", GetUserData).Methods("GET")                               // no validation
	userRouter.HandleFunc("/validatePasswordResetToken", validatePasswordResetToken).Methods("GET") // no validation

	userRouter.HandleFunc("/create", Create).Methods("POST")                 // no validation
	userRouter.HandleFunc("/login", Login).Methods("POST")                   // no validation
	userRouter.HandleFunc("/initialSetup", InitialSetup).Methods("POST")     // validation required
	userRouter.HandleFunc("/forgotPassword", ForgotPassword).Methods("POST") // no validation
	userRouter.HandleFunc("/resetPassword", ResetPassword).Methods("POST")   // no validation
	userRouter.HandleFunc("/updateProfile", UpdateProfile).Methods("POST")   // validation required
	userRouter.HandleFunc("/changeUsername", ChangeUsername).Methods("POST") // validation required
	userRouter.HandleFunc("/changePassword", ChangePassword).Methods("POST") // validation required

	userRouter.HandleFunc("/logout", Logout).Methods("DELETE")
	userRouter.HandleFunc("/removeBirthday", RemoveBirthday).Methods("DELETE") // validation required
	userRouter.HandleFunc("/deleteAccount", DeleteAccount).Methods("DELETE")   // validation required
}
