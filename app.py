from flask import Flask, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_restplus import Api, Resource, abort
from flask_marshmallow import Marshmallow
from flask_migrate import Migrate
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
ma = Marshmallow(app)
api = Api(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

    def __repr__(self):
        return '<User %r>' % self.username


class School(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    principal = db.Column(db.String(80))
    location = db.Column(db.String(120), unique=True, nullable=False)

    def __repr__(self):
        return '<School %r>' % self.name


class SchoolSchema(ma.ModelSchema):
    class Meta:
        model = School


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return {'message': 'Token is missing!'}, 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(slug=data['slug']).first()
        except:
            return {'message': 'Token is invalid!'}, 401

        return f(current_user, *args, **kwargs)
    return decorated


@api.route('/register')
class Register(Resource):
    def post(self):
        data = request.json

        hashed_password = generate_password_hash(data.get('password'), method='sha256')

        new_user = User(slug=str(uuid.uuid4()), username=data.get('username'), password=hashed_password, admin=False)
        db.session.add(new_user)
        db.session.commit()
        user = User.query.filter_by(username=data.get('username')).first()
        user_data = {'slug': user.slug,
                     'username': user.username,
                     'admin': user.admin}
        token = jwt.encode({'slug': user.slug, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
                           app.config['SECRET_KEY'])
        return {'message': 'New user created!', 'user': user_data, 'token': token.decode('UTF-8')}, 201


@api.route('/login')
class Login(Resource):
    @api.expect(User)
    def post(self):
        auth = request.json

        if not auth or not auth.get('username') or not auth.get('password'):
            return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

        user = User.query.filter_by(username=auth.get('username')).first()

        if not user:
            return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

        if check_password_hash(user.password, auth.get('password')):
            token = jwt.encode({'slug': user.slug, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
                               app.config['SECRET_KEY'])
            user_data = {'slug': user.slug,
                         'username': user.username,
                         'admin': user.admin}
            return {'user': user_data, 'token': token.decode('UTF-8')}

        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


@api.route('/hello')
class Hello(Resource):
    def get(self):
        return {'hi': 'hello'}


@api.route('/schools')
class SchoolList(Resource):
    @token_required
    def get(user, self):
        slist = School.query.all()
        school_schema = SchoolSchema(many=True)
        schools = school_schema.dump(slist).data
        return {'schools': schools}


@api.route('/school/<int:pk>')
class SchoolDetail(Resource):
    @token_required
    def get(user, self, pk):
        school_data = School.query.get(pk)
        if not school_data:
            abort(404, error="school {} not found".format(pk))
        school_schema = SchoolSchema()
        school = school_schema.dump(school_data).data
        return {'school': school}


@api.route('/school/new')
class SchoolCreate(Resource):
    @api.expect(School, validate=True)
    def post(self):
        school_schema = SchoolSchema()
        school = school_schema.load(request.json)
        try:
            db.session.add(school.data)
            db.session.commit()
        except Exception as e:
            abort(400, 'School Not Created', error="{}".format(e))
        school_return = school_schema.dump(School.query.filter_by(**request.json).first()).data
        return {'school': school_return}, 201


@api.route('/school/<int:pk>/update')
class SchoolUpdate(Resource):
    def post(self, pk):
        school = School.query.get(pk)
        if not school:
            abort(404, error="school {} not found".format(pk))
        for k, v in request.json.items():
            if hasattr(school, k):
                if v:
                    setattr(school, k, v)
        try:
            db.session.commit()
        except Exception as e:
            abort(400, 'School Not Updated', error="{}".format(e))
        school_schema = SchoolSchema()
        return {'school': school_schema.dump(school).data}


@api.route('/school/<int:pk>/delete')
class SchoolDelete(Resource):
    def get(self, pk):
        school_data = School.query.get(pk)
        if not school_data:
            abort(404, error="school {} not found".format(pk))
        try:
            db.session.delete(school_data)
            db.session.commit()
        except:
            abort(400, "Not Deleted")
        return {'school': 'School {} Deleted'.format(pk)}


if __name__ == '__main__':
    app.run(debug=True)
