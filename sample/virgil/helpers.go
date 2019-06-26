package virgil

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/pkg/errors"
	"gopkg.in/virgil.v4/virgilapi"
)

func InitVirgilCard(email string) (*virgilapi.Key, error) {

	api, _ := virgilapi.New("")

	key, err := api.Keys.Load(email, "password")

	if err == nil {
		return key, nil
	}

	key, _ = api.Keys.Generate()

	card, _ := api.Cards.CreateGlobal(email, key)

	actionId, err := api.Cards.VerifyIdentity(email)
	if err != nil {
		return nil, err
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter confirmation code: ")
	code, _ := reader.ReadString('\n')
	code = code[:len(code)-1]

	token, err := api.Cards.ConfirmIdentity(actionId, code)
	if err != nil {
		return nil, err
	}

	card, err = api.Cards.PublishGlobal(card, token)

	if err != nil {
		return nil, err
	}

	key.Save(email, "password")

	return key, err
}

func GetIdentityAndSignature(data []byte) (identity string, signature []byte, err error) {
	var info *AuthInfo
	err = json.Unmarshal(data, &info)
	if err != nil {
		return
	}

	identity = Identity
	signature = Signature
	return
}

var identityCardsMap = map[string][]*virgilapi.Card{}

func ValidateSignature(data, signature virgilapi.Buffer, identity string) (err error) {

	cards, ok := identityCardsMap[identity]

	if !ok {
		api, _ := virgilapi.New("")

		cards, err = api.Cards.FindGlobal("email", identity)

		identityCardsMap[identity] = cards
	}

	for _, card := range cards {
		if ok, err = card.Verify(data, signature); ok {
			return nil
		}
	}

	return errors.New("could not validate signature for given identity")
}
