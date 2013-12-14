using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Data.Entity.Validation;
using System.Linq;
using System.Text;

namespace CoreRG
{
    /// <summary>
    /// C = DataContext Name
    /// T = Classe do Data Context
    /// Para Instanciar os objetos do framework faca:
    /// IgenericRepository<CLASSE> _repositoryClass;
    /// public Class()
    /// {
    ///     _repositoryClass = new EntityFrameworkRepository<DataContext, DContextClasse>();
    ///     Usage: 
    ///     var model = _repositoryClass.GetAll();
    /// </summary>
    /// <typeparam name="C"></typeparam>
    /// <typeparam name="T"></typeparam>
    public class EntityFrameworkRepository<C, T> : IGenericRepository<T>, IDisposable
        where T : class
        where C : DbContext, new()
    {

        private C _entities = new C();
        public C Context
        {
            get { return _entities; }
            set { _entities = value; }
        }

        /// <summary>
        /// Traz uma coleção de registros
        /// </summary>
        /// <returns></returns>
        public virtual IQueryable<T> GetAll()
        {
            IQueryable<T> query = _entities.Set<T>();
            return query;
        }
        /// <summary>
        /// Traz uma coleção de registro de acordo com a expressao Lambda, informada.
        /// </summary>
        /// <param name="predicate"></param>
        /// <returns></returns>
        public IQueryable<T> GetAllBy(System.Linq.Expressions.Expression<Func<T, bool>> predicate)
        {
            IQueryable<T> query = _entities.Set<T>().Where(predicate);
            return query;
        }

        /// <summary>
        /// Procura um elemento de uma entidade atraves do ID.
        /// </summary>
        /// <param name="Id"></param>
        /// <returns></returns>
        public T FindById(int Id)
        {
            return _entities.Set<T>().Find(Id);
        }

        /// <summary>
        /// Traz um registro de acordo com a expressão lambda passada a função findBy
        /// </summary>
        /// <param name="predicate"></param>
        /// <returns></returns>
        public IQueryable<T> FindBy(System.Linq.Expressions.Expression<Func<T, bool>> predicate)
        {
            IQueryable<T> query = _entities.Set<T>().Where(predicate);
            return query;
        }


        /// <summary>
        /// Retorna o primeiro elemento de uma sequencia, entidade de acordo com a expressao lambda informada, Retorna o primeiro item ou o valor padrão.
        /// </summary>
        /// <param name="predicate"></param>
        /// <returns></returns>
        public T FirstOrDefault(System.Linq.Expressions.Expression<Func<T, bool>> predicate)
        {
            return _entities.Set<T>().Where(predicate).FirstOrDefault();
        }

        /// <summary>
        /// Retorna a quantidade de elementos de uma sequencia, de acordo com a expressão
        /// 
        /// </summary>
        /// <param name="predicate"></param>
        /// <returns></returns>
        public int GetItensCount(System.Linq.Expressions.Expression<Func<T, bool>> predicate)
        {
            int i = _entities.Set<T>().Where(predicate).Count();
            return i;
        }

        /// <summary>
        /// Adiciona uma entidade ou coleção de items da entidade
        /// </summary>
        /// <param name="entity"></param>
        public virtual void Add(T entity)
        {
            _entities.Set<T>().Add(entity);
        }

        /// <summary>
        /// Salva e não da retorno.
        /// é mais usado edição e deleção de dados. combinado com os métodos Edit ou Delete.
        /// </summary>
        public virtual void Save()
        {
            _entities.SaveChanges();
        }

        /// <summary>
        /// Salva os dados(entidade) e retorna maior que 0; caso salvou. Senão < 0 caso não salvou.
        /// </summary>
        /// <param name="entity"></param>
        /// <returns></returns>
        public virtual bool Save(T entity)
        {
            try
            {
                _entities.Entry(entity).State = System.Data.Entity.EntityState.Added;
                int i = _entities.SaveChanges();
                return i > 0;
            }
            catch (DbEntityValidationException ex)
            {
                foreach (var error in ex.EntityValidationErrors)
                {
                    Console.WriteLine("Entity of type \"{0}\" in state \"{1}\" has the following validation errors:",
                    error.Entry.Entity.GetType().Name, error.Entry.State);
                    foreach (var ve in error.ValidationErrors)
                    {
                        Console.WriteLine("-Property: \"{0}\", Error: \"{1}\"",
                                                 ve.PropertyName, ve.ErrorMessage);
                    }
                }
                throw;
            }


            //ctx.Entry(pagina).State = pagina.id_pagina == 0 ? EntityState.Added : EntityState.Modified;
            //int i = ctx.SaveChanges();
            //return i > 0;
        }
        /// <summary>
        /// Edita os dados com o ID da entidade retornando maior que 0 se salvou a edição se nao retorna 0 cas nao tenha salvado
        /// </summary>
        /// <param name="entity"></param>
        /// <returns></returns>
        public bool Edit(T entity)
        {
            try
            {
                _entities.Entry(entity).State = System.Data.Entity.EntityState.Modified;
                int i = _entities.SaveChanges();
                return i > 0;
            }
            catch (DbEntityValidationException ex)
            {
                foreach (var error in ex.EntityValidationErrors)
                {
                    Console.WriteLine("Entity of type \"{0}\" in state \"{1}\" has the following validation errors:",
                    error.Entry.Entity.GetType().Name, error.Entry.State);
                    foreach (var ve in error.ValidationErrors)
                    {
                        Console.WriteLine("-Property: \"{0}\", Error: \"{1}\"",
                                                 ve.PropertyName, ve.ErrorMessage);
                    }
                }

            }
            return false;
        }


        /// <summary>
        /// Deleta os dados de uma entidade, retornando maior que 0, se a entidade foi deletada.
        /// </summary>
        /// <param name="entity"></param>
        /// <returns></returns>
        public bool Delete(T entity)
        {
            try
            {
                _entities.Entry(entity).State = System.Data.Entity.EntityState.Deleted;
                int i = _entities.SaveChanges();
                return i > 0;
            }
            catch (DbEntityValidationException ex)
            {
                foreach (var error in ex.EntityValidationErrors)
                {
                    Console.WriteLine("Entity of type \"{0}\" in state \"{1}\" has the following validation errors:",
                    error.Entry.Entity.GetType().Name, error.Entry.State);
                    foreach (var ve in error.ValidationErrors)
                    {
                        Console.WriteLine("-Property: \"{0}\", Error: \"{1}\"",
                                                 ve.PropertyName, ve.ErrorMessage);
                    }
                }

            }
            return false;
        }


        //Interfaces para tabela de usuarios
        /// <summary>
        /// Retorna uma lista de usuarios.
        /// </summary>
        /// <returns></returns>
        public IQueryable<T> GetAllUsers()
        {
            IQueryable<T> query = _entities.Set<T>();
            return query;
        }

        /// <summary>
        /// Retorna uma lista de usuarios de acordo com a expressão/condição Lambda informada
        /// </summary>
        /// <param name="predicate"></param>
        /// <returns></returns>
        public IQueryable<T> GetAllUsersBy(System.Linq.Expressions.Expression<Func<T, bool>> predicate)
        {
            IQueryable<T> query = _entities.Set<T>().Where(predicate);
            return query;
        }


        public void Dispose()
        {
            if (_entities != null)
                _entities.Dispose();
            if (Context != null)
                Context.Dispose();
        }
    }
}
