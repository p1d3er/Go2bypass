package endecrypt

func StrByXOR(message string) string {
	keywords := "Go2Bypass"
	messageLen := len(message)
	keywordsLen := len(keywords)

	result := ""

	for i := 0; i < messageLen; i++ {
		result += string(message[i] ^ keywords[i%keywordsLen])
	}
	return result
}
