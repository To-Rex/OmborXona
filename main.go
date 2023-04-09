package main

import (
	"database/sql"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

const (	//baza bilan bog'lanish uchun
	host     = "containers-us-west-87.railway.app" 		//host
	port     = 7572										//port
	user	 = "postgres"								//foydalanuvchi
	password = "4aMQQl5p9qnUD52lJaaL"					//parol
	dbname   = "railway"								//baza nomi
)

type User struct {	//foydalanuvchi
	ID 	  	    int       `json:"id"`			//id
	Username    string	  `json:"username"`		//login
	Email       string	  `json:"email"`		//email
	Password    string	  `json:"password"`		//parol
	Name        string	  `json:"name"`			//ismi
	Surname     string	  `json:"surname"`		//familiyasi
	Age         int       `json:"age"`			//yoshi
	Phone       string    `json:"phone"`		//telefon raqami
	Promocode   string	  `json:"promocode"`	//promokod
	Status   	string	  `json:"status"`		//holati
	Roles    	string	  `json:"roles"`		//roli
	City 	  	string	  `json:"city"`			//shahri
	CreatedAt	time.Time `json:"created_at"`	//yaratilgan vaqti
	Token    	string	  `json:"token"`		//tokeni
	Blocked   	bool 	  `json:"blocked"`		//bloklanganmi
	WarehouseID int		  `json:"warehouse_id"` //ombor id
}

type Warehouse struct {			//ombor
	ID 	  	  int   	 `json:"id"`			//id
	Name      string 	 `json:"name"`			//nomi
	City 	  string	 `json:"city"`			//shahri
	CreatedAt time.Time  `json:"created_at"`	//yaratilgan vaqti
	CreatedBy string	 `json:"created_by"`	//yaratgan foydalanuvchi
	Status    string	 `json:"status"`		//holati
	Blocked   bool 		 `json:"blocked"`		//bloklanganmi
}

type Category struct {	//kategoriyalar
	ID 	  	  		int    		`json:"id"`			 //id
	CatID     		string      `json:"cat_id"`		 //kategoriyasi
	Name     		string 		`json:"name"`		 //nomi
	Description 	string	    `json:"description"` //eslatma
	CreatedAt 		time.Time   `json:"created_at"`	 //yaratilgan vaqti
	CreatedBy 		string      `json:"created_by"`	 //yaratgan foydalanuvchi
	Status    		string      `json:"status"`		 //holati
	WarehouseID 	int 		`json:"warehouse_id"`//qaysi omborda
}

type Product struct {	//mahsulot
	ID 	  	  		int    		`json:"id"`		 	 //id
	CatID 			string		`json:"cat_id"` 	 //kategoriyasi
	ProductID     	string      `json:"product_id"`  //mahsulot id
	WarehouseID 	float64 	`json:"warehouse_id"`//qaysi omborda
	Name     		string 		`json:"name"`		 //nomi
	Description 	string	    `json:"description"` //eslatma
	Price 			float64		`json:"price"`       //sotish narxi
	Benicifits 		float64		`json:"benicifits"`  //foydasi
	Discount 		float64		`json:"discount"`    //skidka
	Currency 		string		`json:"currency"`    //valyuta
	Quantity 		float64		`json:"quantity"`    //miqdori
	Measurement 	string		`json:"measurement"` //o'lchov birligi
	Parts 			string		`json:"parts"`		 //qismi - partiya
	Barcode 		string		`json:"barcode"` 	 //barkod
	Brand 			string		`json:"brand"`		 //brendi
	Type 			string		`json:"type"`  		 //turi - tipi
	CreatedAt 		time.Time   `json:"created_at"`	 //yaratilgan vaqti
	CreatedBy 		string      `json:"created_by"`	 //yaratgan foydalanuvchi
	Status    		string      `json:"status"`		 //holati
}

func generateUserId() string {					//yangi shifrlangan id yaratish
	rand.Seed(time.Now().UnixNano())			//random raqam yaratish
	chars := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")	//harflar
	length := 32								//uzunligi	
	b := make([]rune, length)					//uzunlikdagi massiv
	for i := range b {							//massivni to'ldirish
		b[i] = chars[rand.Intn(len(chars))]		//harflardan random tanlash
	}
	return string(b)							//stringga o'tkazish
}

func passwordHash(password string) string {							//parolni shifrlash
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)	//parolni shifrlash
	if err != nil {
		fmt.Println(err)
	}
	return string(hash)
}

func checkPasswordHash(password, hash string) bool {						//parolni tekshirish
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))	//parolni tekshirish
	return err == nil														//agar xato bo'lmasa true qaytaradi
}

func generateToken(username string, password string, roles string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"password": password,
		"created_at": time.Now(),
		"roles": roles,
	})
	tokenString, err := token.SignedString([]byte("secret"))
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	return tokenString, nil
}

func main() {
	r := gin.Default()
	r.POST("/register", register)
	r.POST("/login", login)
	r.POST("/logout", logout)
	r.POST("/addWarehouse", addWarehouse)
	r.POST("/addCategory", addCategory)
	r.Run()
}

func connectDB() *sql.DB {
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+ "password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)
	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		panic(err)
	}
	err = db.Ping()
	if err != nil {
		panic(err)
	}
	return db
}

func register(c *gin.Context) {
	var user User
	err := c.BindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	db := connectDB()
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username TEXT, email TEXT, password TEXT, name TEXT, surname TEXT, age INT,  phone TEXT, promocode TEXT, status TEXT, roles TEXT, city TEXT, created_at TIMESTAMP, token TEXT, blocked BOOLEAN, warehouse_id INT)")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	user.Promocode = ""
	user.Status = "active"
	user.Roles = "user"
	user.CreatedAt = time.Now()
	user.Token = " "
	user.Blocked = false

	if user.Username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username is empty"})
		return
	}
	if user.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email is empty"})
		return
	}
	if user.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password is empty"})
		return
	}
	if user.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is empty"})
		return
	}
	if user.Surname == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "surname is empty"})
		return
	}
	if user.Phone == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "phone is empty"})
		return
	}

	if user.Age == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "age is empty"})
		return
	}

	if  user.Age < 16 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "age is less than 16"})
		return
	}

	if user.City == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "city is empty"})
		return
	}

	//db in warehouse table in get all id if WarehouseID == warehouse table in list id element in id == WarehouseID create user 
	idList := []int{}
	rows, err := db.Query("SELECT id FROM warehouses")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	for rows.Next() {
		var id int
		err = rows.Scan(&id)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		idList = append(idList, id)
	}
	//if user.WarehouseID == idList {
		for _, id := range idList {
			if user.WarehouseID != id {
				c.JSON(http.StatusBadRequest, gin.H{"error": "warehouse id is not exist"})
				return
			}else {
				fmt.Println("ok")
				break
			}
		}
		
	var username string
	err = db.QueryRow("SELECT username FROM users WHERE username = $1", user.Username).Scan(&username)
	if err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username already exist"})
		return
	}

	_, err = db.Exec("INSERT INTO users (username, email, password, name, surname, age, phone, promocode, status, roles, city, created_at, token, blocked, warehouse_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)", user.Username, user.Email, passwordHash(user.Password), user.Name, user.Surname, user.Age, user.Phone, user.Promocode, user.Status, user.Roles, user.City, user.CreatedAt, user.Token, user.Blocked, user.WarehouseID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func login(c *gin.Context) {
	var user User
	err := c.BindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	db := connectDB()
	var username string
	var password string
	var token string
	var roles string
	err = db.QueryRow("SELECT username, password, token, roles FROM users WHERE username = $1", user.Username).Scan(&username, &password, &token, &roles)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "username or password is incorrect"})
		return
	}

	if !checkPasswordHash(user.Password, password) {
		fmt.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "username or password is incorrect"})
		return
	}

	if token == " " ||token != " " {
		token, err = generateToken(username, password,roles)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		_, err = db.Exec("UPDATE users SET token = $1 WHERE username = $2", token, username)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

func logout(c *gin.Context) {
	token := c.GetHeader("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")
	claims := jwt.MapClaims{}
	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !tkn.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	db := connectDB()
	_, err = db.Exec("UPDATE users SET token = $1 WHERE username = $2", "", claims["username"])
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func addWarehouse(c *gin.Context) {
	//if such a name exists error else add warehouse to db name, address, phone, city, status, created_at, created_by = username 
	token := c.GetHeader("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")
	claims := jwt.MapClaims{}
	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil 
	})

	if (claims["roles"] != "boss") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "you are not boss"})
		return
	}

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !tkn.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var warehouse Warehouse
	err = c.BindJSON(&warehouse)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if warehouse.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is empty"})
		return
	}

	if warehouse.City == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "city is empty"})
		return
	}

	warehouse.CreatedAt = time.Now()
	warehouse.CreatedBy = claims["username"].(string)
	warehouse.Status = "active"
	warehouse.Blocked = false

	db := connectDB()
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS warehouses (id SERIAL PRIMARY KEY, name TEXT, city TEXT, created_at TIMESTAMP, created_by TEXT, status TEXT, blocked BOOLEAN)")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var name string
	err = db.QueryRow("SELECT name FROM warehouses WHERE name = $1", warehouse.Name).Scan(&name)
	if err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name already exist"})
		return
	}

	_, err = db.Exec("INSERT INTO warehouses (name, city, created_at, created_by, status, blocked) VALUES ($1, $2, $3, $4, $5, $6)", warehouse.Name, warehouse.City, warehouse.CreatedAt, warehouse.CreatedBy, warehouse.Status, warehouse.Blocked)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func addCategory(c *gin.Context) {
	token := c.GetHeader("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")
	claims := jwt.MapClaims{}
	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil 
	} )

	if (claims["roles"] != "boss"){
		c.JSON(http.StatusUnauthorized, gin.H{"error": "you are not creator or boss"})
		return
	}

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !tkn.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var category Category
	err = c.BindJSON(&category)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if category.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is empty"})
		return
	}
	category.CatID = generateUserId() 
	category.CreatedAt = time.Now()
	category.CreatedBy = claims["username"].(string)
	category.Status = "active"

	db := connectDB()
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS categories (id SERIAL PRIMARY KEY, cat_id TEXT, name TEXT, description TEXT, created_at TIMESTAMP, created_by TEXT, status TEXT, warehouse_id INT)")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var name string
	var warehouse_id int
	//if db in name if any and warehouse_id and row in warehouse_id available return error
	err = db.QueryRow("SELECT name, warehouse_id FROM categories WHERE name = $1 AND warehouse_id = $2", category.Name, category.WarehouseID).Scan(&name, &warehouse_id)
	if err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name already exist"})
		return
	}

	_, err = db.Exec("INSERT INTO categories (cat_id, name, description, created_at, created_by, status, warehouse_id) VALUES ($1, $2, $3, $4, $5, $6, $7)", category.CatID, category.Name, category.Description, category.CreatedAt, category.CreatedBy, category.Status, category.WarehouseID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}
