from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_restplus import Api, Resource, abort
from flask_marshmallow import Marshmallow

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)
ma = Marshmallow(app)
api = Api(app)


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


@api.route('/hello')
class Hello(Resource):
    def get(self):
        return jsonify({'hi': 'hello'})


@api.route('/schools')
class SchoolList(Resource):
    def get(self):
        slist = School.query.all()
        school_schema = SchoolSchema(many=True)
        schools = school_schema.dump(slist).data
        return {'schools': schools}


@api.route('/school/<int:pk>')
class SchoolDetail(Resource):
    def get(self, pk):
        school_data = School.query.get(pk)
        if not school_data:
            abort(404, error="school {} not found".format(pk))
        school_schema = SchoolSchema()
        school = school_schema.dump(school_data).data
        return {'school': school}


@api.route('/school/new')
class SchoolCreate(Resource):
    def post(self):
        school_schema = SchoolSchema()
        school = school_schema.load(api.payload)
        try:
            db.session.add(school.data)
            db.session.commit()
        except Exception as e:
            abort(400, 'School Not Created', error="{}".format(e))
        return {'school': api.payload}


@api.route('/school/<int:pk>/update')
class SchoolCreate(Resource):
    def post(self, pk):
        school = School.query.get(pk)
        if not school:
            abort(404, error="school {} not found".format(pk))
        for k, v in api.payload.items():
            if hasattr(school, k):
                if v:
                    setattr(school, k, v)
        try:
            db.session.commit()
        except Exception as e:
            abort(400, 'School Not Updated', error="{}".format(e))
        return {'school': api.payload}

@api.route('/school/<int:pk>/delete')
class SchoolDetail(Resource):
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
    app.run()
