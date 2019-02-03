def int_to_bytes(num):
    # shrug... that's ugly (reconsider...)
    return str(num).encode('ascii')


#
# property accessor stuff
#


# Always use a specific subclass (because we discriminate the "real"
# class from subclasses via a _class_ attribute). For an example usage
# see Properties.define
class PropertyAccessorMetaBase(type):
    def __new__(cls, name, bases, ns):
        if not hasattr(cls, '_name'):
            cls._name = name
        elif cls._name != name:
            # clean ns (let's keep fingers crossed that the class itself
            # does not define a _props or _prop_get for its own purposes...)
            ns.pop('_props', None)
            ns.pop('_prop_get', None)
            return cls._create_class(name, bases, ns)
        props = ns.pop('_props', [])
        prop_get_meth = ns.pop('_prop_get', None)
        accessors = []
        for prop in props:
            meth_name = '_prop_{}_get'.format(prop)
            meth = ns.pop(meth_name, None)
            if prop and meth is None and prop_get_meth is None:
                raise ValueError('props but no prop getter method')
            if meth is None:
                meth = prop_get_meth(prop)
            accessors.append((prop, property(meth)))
        # defer class creation until here: otherwise the _prop* stuff
        # would be part of the class
        new_cls = cls._create_class(name, bases, ns)
        for prop, accessor in accessors:
            setattr(new_cls, prop, accessor)
        return new_cls

    @classmethod
    def _create_class(cls, name, bases, ns):
        return super(PropertyAccessorMetaBase, cls).__new__(cls, name, bases,
                                                            ns)


class Properties(object):
    @staticmethod
    def define(*props, use_cls_prop_get=False):
        def _prop_get(prop):
            def _get(self):
                return getattr(self, '_{}'.format(prop))

            return _get

        class SpecificPropertyAccessorMeta(PropertyAccessorMetaBase):
            def __prepare__(*args, **kwargs):
                ns = PropertyAccessorMetaBase.__prepare__(*args, **kwargs)
                # ignore existing _props (there is no sane reason why
                # Properties.define is used in this case)
                ns['_props'] = props
                if not use_cls_prop_get:
                    ns['_prop_get'] = _prop_get
                return ns

        return {'metaclass': SpecificPropertyAccessorMeta}
