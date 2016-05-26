#ifndef _SLIST_H
#define _SLIST_H

/*
 * Singly-linked Tail queue declarations.
 */
#define STAILQ_HEAD(name, type)                                         \
struct name {                                                           \
        struct type *stqh_first;/* first element */                     \
        struct type **stqh_last;/* addr of last next element */         \
}

#define STAILQ_HEAD_INITIALIZER(head)                                   \
        { NULL, &(head).stqh_first }

#define STAILQ_ENTRY(type)                                              \
struct {                                                                \
        struct type *stqe_next; /* next element */                      \
}

/*
 * Singly-linked Tail queue functions.
 */
#define STAILQ_CONCAT(head1, head2) do {                                \
        if (!STAILQ_EMPTY((head2))) {                                   \
                *(head1)->stqh_last = (head2)->stqh_first;              \
                (head1)->stqh_last = (head2)->stqh_last;                \
                STAILQ_INIT((head2));                                   \
        }                                                               \
} while (0)

#define STAILQ_EMPTY(head)      ((head)->stqh_first == NULL)

#define STAILQ_FIRST(head)      ((head)->stqh_first)

#define STAILQ_FOREACH(var, head, field)                                \
        for((var) = STAILQ_FIRST((head));                               \
           (var);                                                       \
           (var) = STAILQ_NEXT((var), field))

#define STAILQ_FOREACH_SAFE(var, head, field, tvar)                     \
        for ((var) = STAILQ_FIRST((head));                              \
            (var) && ((tvar) = STAILQ_NEXT((var), field), 1);           \
            (var) = (tvar))

#define STAILQ_INIT(head) do {                                          \
        STAILQ_FIRST((head)) = NULL;                                    \
        (head)->stqh_last = &STAILQ_FIRST((head));                      \
} while (0)

#define STAILQ_INSERT_AFTER(head, tqelm, elm, field) do {               \
        if ((STAILQ_NEXT((elm), field) = STAILQ_NEXT((tqelm), field)) == NULL)\
                (head)->stqh_last = &STAILQ_NEXT((elm), field);         \
        STAILQ_NEXT((tqelm), field) = (elm);                            \
} while (0)

#define STAILQ_INSERT_HEAD(head, elm, field) do {                       \
        if ((STAILQ_NEXT((elm), field) = STAILQ_FIRST((head))) == NULL) \
                (head)->stqh_last = &STAILQ_NEXT((elm), field);         \
        STAILQ_FIRST((head)) = (elm);                                   \
} while (0)

#define STAILQ_INSERT_TAIL(head, elm, field) do {                       \
        STAILQ_NEXT((elm), field) = NULL;                               \
        *(head)->stqh_last = (elm);                                     \
        (head)->stqh_last = &STAILQ_NEXT((elm), field);                 \
} while (0)

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#ifndef container_of
/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:    the pointer to the member.
 * @type:   the type of the container struct this is embedded in.
 * @member: the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({          \
    const typeof(((type *)0)->member) * __mptr = (ptr); \
    (type *)((char *)__mptr - offsetof(type, member)); })
#endif

#define STAILQ_LAST(head, type, field)                                  \
        (STAILQ_EMPTY((head)) ? NULL :                                  \
            container_of((head)->stqh_last, struct type, field.stqe_next))

#define STAILQ_NEXT(elm, field) ((elm)->field.stqe_next)

#define QMD_SAVELINK(name, link)
#define TRASHIT(x)
#define STAILQ_REMOVE(head, elm, type, field) do {                      \
        QMD_SAVELINK(oldnext, (elm)->field.stqe_next);                  \
        if (STAILQ_FIRST((head)) == (elm)) {                            \
                STAILQ_REMOVE_HEAD((head), field);                      \
        }                                                               \
        else {                                                          \
                struct type *curelm = STAILQ_FIRST((head));             \
                while (STAILQ_NEXT(curelm, field) != (elm))             \
                        curelm = STAILQ_NEXT(curelm, field);            \
                STAILQ_REMOVE_AFTER(head, curelm, field);               \
        }                                                               \
        TRASHIT(*oldnext);                                              \
} while (0)

#define STAILQ_REMOVE_AFTER(head, elm, field) do {                      \
        if ((STAILQ_NEXT(elm, field) =                                  \
             STAILQ_NEXT(STAILQ_NEXT(elm, field), field)) == NULL)      \
                (head)->stqh_last = &STAILQ_NEXT((elm), field);         \
} while (0)

#define STAILQ_REMOVE_HEAD(head, field) do {                            \
        if ((STAILQ_FIRST((head)) =                                     \
             STAILQ_NEXT(STAILQ_FIRST((head)), field)) == NULL)         \
                (head)->stqh_last = &STAILQ_FIRST((head));              \
} while (0)

#define STAILQ_SWAP(head1, head2, type) do {                            \
        struct type *swap_first = STAILQ_FIRST(head1);                  \
        struct type **swap_last = (head1)->stqh_last;                   \
        STAILQ_FIRST(head1) = STAILQ_FIRST(head2);                      \
        (head1)->stqh_last = (head2)->stqh_last;                        \
        STAILQ_FIRST(head2) = swap_first;                               \
        (head2)->stqh_last = swap_last;                                 \
        if (STAILQ_EMPTY(head1))                                        \
                (head1)->stqh_last = &STAILQ_FIRST(head1);              \
        if (STAILQ_EMPTY(head2))                                        \
                (head2)->stqh_last = &STAILQ_FIRST(head2);              \
} while (0)

#endif
