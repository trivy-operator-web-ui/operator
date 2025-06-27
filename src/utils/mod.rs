use kube::api::ObjectMeta;

pub trait Simplify {
    fn simplify(&mut self);
}

impl Simplify for ObjectMeta {
    fn simplify(&mut self) {
        self.finalizers = None;
        self.managed_fields = None;
        self.generation = None;
        self.creation_timestamp = None;
        self.annotations = None;
        self.owner_references = None;
        self.resource_version = None;
        self.labels = None;
    }
}
