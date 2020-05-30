const bcrypt = require('bcryptjs');
const md5 = require('md5');

global._this = null;

class UsersAPI {

    static AUTO_GENERATE_ALLOWS = [
        'id',
        'createAt',
        'token'
    ];

    static STORAGE_METHODS_NAME_IMPLEMENTS = [
        'addUser',
        'authentication',
        'getUserById',
        'getUsersBy'
    ];

    static STORAGE_SHOULD_HAVE_FUNC = [
        'getDocsList',
        'addCollection',
        'addDoc',
        'getDoc',
        'getDocByDocname'
    ];

    constructor( {
        collectionName="users",
        autoGenerate,
        uniqKeys,
        constraintsAuthentication,
        passwordHash
    } ) {

        global._this = this;

        this.collectionName = collectionName;
        this.autoGenerate = autoGenerate;
        this.constraintsAuthentication = constraintsAuthentication;
        this.uniqKeys = uniqKeys;

        this.passwordHash  = passwordHash;

        this.normalizeListKeys( 'autoGenerate' );
        this.normalizeListKeys( 'uniqKeys' );
    }

    isAlreadyExists( keyName, value ) {

        const docsname = global._this.getDocsList( global._this.collectionName );

        let isExists = false;

        docsname.forEach( docname => {

            const doc = global._this.getDocByDocname( docname );

            if( doc[ keyName ] === value ) {

                isExists = true;
            }

        } );

        return isExists;
    }

    addUser( user ) {

        if( typeof user !== "object" ) {

            throw new RangeError('UsersAPI error: addUser arg1: user should be a object');
        }

        Object.keys( user ).forEach( attribute => {

            if( user[ attribute ] instanceof Function ) { // no serialize

                delete user[ attribute ];
            }
        } );

        global._this.autoGenerate.forEach( keyAutoGenerate => {

            const methodName = `autoGenerate${keyAutoGenerate.charAt(0).toLocaleUpperCase() + keyAutoGenerate.slice(1,)}`
            user[ keyAutoGenerate ] = UsersAPI[ methodName ]();

        } );

        let isUniqKeysError = false;
        const uniqKeysError = [];

        if( global._this.uniqKeys.length ) {

            global._this.uniqKeys.forEach( uniqKey => {

                const value = user[ uniqKey ];

                if( !!value ) {

                    if( global._this.isAlreadyExists( uniqKey, value ) ) {

                        isUniqKeysError = true;
                        uniqKeysError.push( uniqKey );
                    }
                }

            } );
        }

        if( isUniqKeysError ) {

            return {
                success: false,
                error: 'violation constraint unique key',
                uniqKeysError
            };
        }

        if( global._this.passwordHash ) {

            if( typeof user.password !== 'string' ) {

                throw new RangeError('property password of a user should be exists');

            } else {
                user.password = bcrypt.hashSync(
                    user.password,
                    bcrypt.genSaltSync( global._this.passwordHash.cost )
                );
            }
        }

        this.addDoc(
            global._this.collectionName,
            user
        );

        return {
            success: true,
            user
        };
    }

    getUserById( userId ) {

        const user = global._this.getUsersBy( {
            id: userId
        } );

        return user[0] || null;
    }

    getUsersBy( matcher ) {

        const docsname = global._this.storage.getDocsList( global._this.collectionName );

        const users = [];

        docsname.forEach( docname => {

            const doc = global._this.storage.getDocByDocname( docname );

            let isMatches = true;

            Object.keys( matcher ).forEach( attribute => {

                if( matcher[ attribute ] !== doc[ attribute ] ) {

                    isMatches = false;
                }

            } );

            if( isMatches ) {

                users.push( doc );
            }

        } );

        return users;
    }

    authentication( credentials ) {

        if( typeof credentials !== "object" ) {

            throw new RangeError("UsersAPI error: method authentication arg1: should be a object: { plainPassword: string, login: string }");
        }

        const plainPassword = typeof credentials.password === "string" ? credentials.password: credentials.plainPassword;

        let login = credentials.login;

        if( !login && Object.keys( credentials ).length > 1 ) {

            login = global._this.resolveLoginAuthentication( credentials );
        } else {

            const value = login;

            login = {
                keyName: "email",
                value
            };
        }

        if( typeof plainPassword !== "string" || typeof login.value !== "string" ) {

            throw new RangeError('UserAPI error: method authentication attribute plainPassword and login should be string value');
        }

        const docsname = this.getDocsList( global._this.collectionName );

        let isLoginExists = false;
        let isAuthenticationSuccess = false;
        let isConstraintsAuthentication = false;
        let constraintsAuthentication = [];
        let user = null;

        docsname.forEach( docname => {

            const doc = this.getDocByDocname( docname );

            if( doc[ login.keyName ] === login.value ) { // login found

                isLoginExists = true;
                isAuthenticationSuccess = !!global._this.passwordHash ? bcrypt.compareSync( plainPassword, doc.password ): plainPassword === doc.password ;

                if( !!global._this.constraintsAuthentication ) {

                    Object.keys( global._this.constraintsAuthentication ).forEach( keyConstraint => {

                        if( doc[ keyConstraint ] !== global._this.constraintsAuthentication[ keyConstraint ] ) { // e.g: isValidateAccount, isRemoveAccount, ...

                            isConstraintsAuthentication = true;
                            constraintsAuthentication.push( keyConstraint );
                        }
                    } );

                } else {

                    isConstraintsAuthentication = false;
                }

                if( !isConstraintsAuthentication && isAuthenticationSuccess ) {

                    user = doc;
                }
            }

        } );

        return global._this.authenticationResponse( {
            isLoginExists,
            isAuthenticationSuccess,
            isConstraintsAuthentication,
            constraintsAuthentication,
            credentials: {
                login,
                plainPassword
            },
            user
        } );

    }

    addUsersCollection() {

        this.storage.addCollection( this.collectionName );
    }

    static autoGenerateId() {

        const strRand = () => (
            Math.random().toString().replace('.','')
        );

        const hash = md5( strRand() );

        let id = `${Date.now().toString()}${hash.slice( 0, 16 )}${strRand()}${hash.slice( 16,32 )}`;

        return id;
    }

    static autoGenerateCreateAt() {

        return Date.now();
    }

    static autoGenerateToken() {

        return md5( ( Date.now().toString() + Math.random().toString() ) );
    }

    resolveLoginAuthentication( credentials ) {

        const reserved = ['password','plainPassword'];

        let login = {};

        Object.keys( credentials ).forEach( attribute => {

            if( !reserved.includes(attribute) ) {

                login.keyName = attribute;
                login.value = credentials[ attribute ];
            }

        } );

        return login;
    }

    authenticationResponse( {
        isLoginExists,
        isAuthenticationSuccess,
        isConstraintsAuthentication,
        constraintsAuthentication,
        credentials: {
            login,
            plainPassword
        },
        user
    } ) {

        const response = { isLoginExists };

        if( !isAuthenticationSuccess ) {

            response.success = false;

            if( !isLoginExists ) {

                response.error = `"${login.keyName}" with value: "${login.value}", not exists`
            } else {

                response.error = `couple: (${login.value}, ${plainPassword}) not exists`
            }

        } else {

            if( !isConstraintsAuthentication ) {

                response.success = true;
            } else {
                response.success = false;
                response.error = `constrainst: "${constraintsAuthentication.join(', ')}" have blocked authentication`
                response.constraintsAuthentication = constraintsAuthentication;
            }
        }

        if( !!response.error ) {

            if( !isConstraintsAuthentication ) {
                response.errorMuted = "credentials error";
            } else {
                response.errorMuted = "authentication reject"
            }
        }

        if( response.success ) {

            response.user = user;
        }

        return response;
    }

    normalizeListKeys( attributeName ) {

        if( !(this[attributeName] instanceof Array) ) {

            throw new RangeError('UsersAPI internal error: normalizeListKey arg1: list, should be a array');
        }

        this[ attributeName ] = this[ attributeName ]
            .filter( key => typeof key === "string" )
            .map( key => key.trim() )
        ;
    }

    implementStorage() {

        UsersAPI.STORAGE_METHODS_NAME_IMPLEMENTS.forEach( methodName => {

            if( this.storage[ methodName ] instanceof Function ) {

                throw new RangeError('UsersAPI storage error: you cant implement UsersAPI on this storage because already have users interface');
            } else {

                this.storage[ methodName ] = this[methodName];
            }

        } );
    }

    get storage() {
        return this._storage;
    }
    set storage( storage ) {

        this._storage = typeof storage === "object" ? storage: null;

        if( typeof this._storage === "object" ) {

            UsersAPI.STORAGE_SHOULD_HAVE_FUNC.forEach( funcName => {

                if( !( this._storage[ funcName ] instanceof Function ) ) {

                    throw new RangeError('UsersAPI errro: set storage with a not recognize storage object.');
                }

            } );

        } else {

            throw new RangeError('UsersAPI errro: set storage with a not object.')
        }

        this.implementStorage();
    }

    get uniqKeys() {
        return this._uniqKeys;
    }
    set uniqKeys(uniqKeys) {
        this._uniqKeys = uniqKeys instanceof Array ? uniqKeys: [];
    }

    /**
     * @return object
     */
    get passwordHash() {
        return this._passwordHash;
    }
    set passwordHash( passwordHash ) {

        if( typeof passwordHash === "string" ) {

            this._passwordHash = {
                cost: 13,
                hash: 'bcrypt'
            };

        } else if( typeof passwordHash === "object" ) {

            this._passwordHash = {
                cost: parseInt(passwordHash.cost || passwordHash.salt) || 13,
                hash: 'bcrypt'
            };

            if( isNaN(this._passwordHash.cost) ) {
                this._passwordHash.cost = 13;
            }

        }
    }

    get collectionName() {
        return this._collectionName;
    }
    set collectionName(collectionName) {

        this._collectionName = typeof collectionName === "string" ? collectionName: null;

        if( !this._collectionName ) {

            this._collectionName = "users";
        }
    }

    get autoGenerate() {
        return this._autoGenerate;
    }
    set autoGenerate(autoGenerate) {

        this._autoGenerate = autoGenerate instanceof Array ? autoGenerate: [
            'id',
            'token'
        ];

        this._autoGenerate.forEach( key => {

            if( !UsersAPI.AUTO_GENERATE_ALLOWS.includes( key ) ) {

                throw new RangeError('UsersAPI constructor error: autoGenerate one or many key not recognize');
            }
        } )
    }

    get constraintsAuthentication() {
        return this._constraintsAuthentication;
    }
    set constraintsAuthentication(constraintsAuthentication) {

        this._constraintsAuthentication = typeof constraintsAuthentication === "object" ? constraintsAuthentication: null;

        if( !!this._constraintsAuthentication ) {

            Object.keys( this._constraintsAuthentication ).forEach( attribute => {

                if( this._constraintsAuthentication[ attribute ] instanceof Function ) {

                    delete this._constraintsAuthentication[ attribute ];
                }

            } );
        }
    }

};

module.exports = UsersAPI;
