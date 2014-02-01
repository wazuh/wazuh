void zeromq_output_event(Eventinfo *lf);
void zeromq_output_start(char *uri, int argc, char **argv);
void zeromq_output_end();
char *Eventinfo_to_jsonstr(Eventinfo *lf);
