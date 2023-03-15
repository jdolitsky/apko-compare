package internal

type ImagePosition int

const (
	ImageNeither ImagePosition = iota
	ImageLeft
	ImageRight
	ImageBoth
)

type Params struct {
	Platforms          []string
	IgnoreContent      bool
	IgnoreSize         bool
	IgnoreTimestamps   bool
	IgnorePermissions  bool
	IgnoreOwnership    bool
	IgnoreMissingImage bool
	IgnoreExtraFiles   ImagePosition
	Username           string
	Password           string
	Proxy              string
	Anonymous          bool
	SaveFilePattern    string
}
