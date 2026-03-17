package enforcer

type filmReadInput struct {
	FilmID        string
	Title         string
	TimeElapsedCT string
}

type filmCreatePlain struct {
	Title       string
	TimeElapsed int
}

type filmCreateEncrypted struct {
	Title         string
	TimeElapsedCT string
}

type filmReadResult struct {
	TimeElapsed     interface{}
	FieldsDecrypted []string
	FieldsMasked    []string
	FieldsDenied    []string
	DecisionHash    string
	PolicyID        string
	PolicyVersion   string
}
