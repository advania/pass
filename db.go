package pass

import (
	"database/sql"
	"net/http"
	"sync"
)

type database interface {
	ping() (err error)
	get(uuid string, sitePassword string) (password string, err error)
	create(password string, sitePassword string) (uuid string, err error)
	close()
}

type mustDatabaseConnect struct {
	dbHandle database
	mutex    sync.Mutex
	connect  func() (db database, err error)
}

func (nfp *mustDatabaseConnect) doConnect() (err error) {
	nfp.mutex.Lock()
	defer nfp.mutex.Unlock()

	if nfp.dbHandle == nil {
		var err error
		if nfp.dbHandle, err = nfp.connect(); err != nil {
			return err
		}
	}

	return nil
}

func (nfp *mustDatabaseConnect) ping() (err error) {
	if err := nfp.doConnect(); err != nil {
		return err
	}

	return nfp.dbHandle.ping()
}

func (nfp *mustDatabaseConnect) get(uuid string, sitePassword string) (password string, err error) {
	if err := nfp.doConnect(); err != nil {
		return "", err
	}

	return nfp.dbHandle.get(uuid, sitePassword)
}

func (nfp *mustDatabaseConnect) create(password string, sitePassword string) (uuid string, err error) {
	if err = nfp.doConnect(); err != nil {
		return "", err
	}

	return nfp.dbHandle.create(password, sitePassword)
}

func (nfp *mustDatabaseConnect) close() {
	nfp.mutex.Lock()
	defer nfp.mutex.Unlock()

	if nfp.dbHandle != nil {
		nfp.dbHandle.close()
		nfp.dbHandle = nil
	}
}

func newMustDatabaseConnect(connect func() (db database, err error)) (dbc *mustDatabaseConnect) {
	return &mustDatabaseConnect{
		dbHandle: nil,
		connect:  connect,
	}
}

type databaseConnection struct {
	db         *sql.DB
	createStmt *sql.Stmt
	getStmt    *sql.Stmt
}

func (pp *databaseConnection) ping() (err error) {
	return pp.db.Ping()
}

func (pp *databaseConnection) get(uuid string, sitePassword string) (password string, err error) {
	var result *sql.Rows

	if result, err = pp.getStmt.Query(uuid, sitePassword); err != nil {
		return "", NewHTTPError(http.StatusInternalServerError, err)
	}
	defer result.Close()

	result.Next()
	result.Scan(&password)

	return password, nil
}

func (pp *databaseConnection) create(password string, sitePassword string) (uuid string, err error) {
	var result *sql.Rows
	if result, err = pp.createStmt.Query(password, sitePassword); err != nil {
		return "", NewHTTPError(http.StatusInternalServerError, err)
	}
	defer result.Close()

	result.Next()
	result.Scan(&uuid)

	return uuid, nil
}

func (pp *databaseConnection) close() {
	if pp != nil {
		pp.getStmt.Close()
		pp.createStmt.Close()
		pp.db.Close()
	}
}

func newDatabaseConnectionVariables(sv *serverVariables) (dbConn database, err error) {
	var db *sql.DB
	if db, err = sql.Open("postgres", sv.cfg.PDOString); err != nil {
		return
	}

	if err = db.Ping(); err != nil {
		return
	}

	if _, err = db.Exec("set session characteristics as transaction isolation level serializable"); err != nil {
		return
	}

	var createStmt *sql.Stmt
	if createStmt, err = db.Prepare("select * from create_password($1, $2)"); err != nil {
		return
	}

	var getStmt *sql.Stmt
	if getStmt, err = db.Prepare("select * from get_password($1, $2)"); err != nil {
		return
	}

	return &databaseConnection{
		db:         db,
		createStmt: createStmt,
		getStmt:    getStmt,
	}, err
}
