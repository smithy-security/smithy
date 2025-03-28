// THIS IS INTENTIONALLY VULNERABLE
// ALL of the below dependencies have CVEs associated with them.
module example.com/myproject

go 1.18

require (
	github.com/aws/aws-sdk-go v1.40.56 // Older version, latest is v1.42.x
	github.com/gin-gonic/gin v1.7.7 // Older version, latest is v1.8.x
	github.com/go-redis/redis/v8 v8.11.4 // Older version, latest is v9.x
	github.com/gorilla/mux v1.8.0 // Older version, latest is v1.9.x
	github.com/jinzhu/gorm v1.9.16 // Older version, latest is v2.x
	github.com/prometheus/client_golang v1.11.0 // Older version, latest is v1.12.x
	github.com/sirupsen/logrus v1.8.1 // Older version, latest is v1.9.x
	github.com/spf13/viper v1.10.0 // Older version, latest is v1.11.x
	github.com/stretchr/testify v1.7.0 // Older version, latest is v1.8.x
	google.golang.org/grpc v1.42.0 // Older version, latest is v1.45.x
)
