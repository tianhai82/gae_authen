package gae_authen

type WrongPasswordError int

func (f WrongPasswordError) Error() string {
	return "Wrong password"
}

type UserNotFound int

func (f UserNotFound) Error() string {
	return "User not found"
}
