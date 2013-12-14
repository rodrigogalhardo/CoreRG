using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Text;

namespace CoreRG
{
    public interface IGenericRepository<T> : IDisposable where T : class
    {
        IQueryable<T> GetAll();
        IQueryable<T> GetAllBy(Expression<Func<T, bool>> predicate);
        IQueryable<T> FindBy(Expression<Func<T, bool>> predicate);
        T FindById(int Id);
        T FirstOrDefault(Expression<Func<T, bool>> predicate);
        int GetItensCount(Expression<Func<T, bool>> predicate);
        void Add(T entity);
        bool Delete(T entity);
        bool Edit(T entity);
        void Save();
        bool Save(T entity);

        IQueryable<T> GetAllUsers();
        IQueryable<T> GetAllUsersBy(Expression<Func<T, bool>> predicate);

    }
}
